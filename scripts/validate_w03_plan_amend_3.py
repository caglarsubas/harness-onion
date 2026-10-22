#!/usr/bin/env python3
"""Validate the MET-ENFORCE-037 W03 obligation-register amendment 3 and the exact 250-to-249 projection."""
from __future__ import annotations

import ast
import base64
import binascii
import copy
import difflib
import hashlib
import json
import re
import stat
import types
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

try:
    from safe_yaml import safe_load
    import validate_lab_run_plan as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_lab_run_plan as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/w03-plan-amend-3-authority.json"
AUTHORITY_SHA256 = "47f271a661c1ba1ceb98e46ea7e4078571cbfd2281ef12eff0c21112560feb87"
VALIDATOR_PATH = "scripts/validate_w03_plan_amend_3.py"
BASE_COMMIT = "a3b9e6e7aedd68e092f3601aa729b61be7241755"
NEW_PACKET = "MET-ENFORCE-037"
PREVIOUS_PACKET = "MET-ENFORCE-036"
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
            require(key not in result, "duplicate w03-plan-amend-3 authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite w03-plan-amend-3 authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "w03 plan amendment 3 history authority digest")
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
    }, "closed w03 plan amendment 3 history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/w03-plan-amend-3-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 249
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 249-packet base")
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
    # An exact 249-era byte string is already older than the successor layer.
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


# MET-ENFORCE-037 (roadmap W03-PLAN-AMEND-3; candidate 5 re-adopted by the lane monitor, owner-delegated, 2026-10-18,
# after four independent review rounds, superseding the candidate-4 adoption) publishes W03 obligation-register amendment
# 3. It applies after amendments 1 and 2, an ordered `after` list: it adds the policy observer's host-policy obligation
# OBS-HOSTPOL-1 (HE-008, T04) and the broker's quiescent-freeze obligation NP-9 (HE-005, HE-004D1, T04); corrects HE-003's
# share in amendment 1's SEC-4 and HI-7 rows as owner decision Q-HE3-3 (a) directs (the closed change kind
# SHARE_CORRECTED, schema v3); and records HE-004D1's packet scope with its owner decisions, hand-offs and accepted
# residuals. Plan v2, amendments 1 and 2, edge record v5 and every file the amendment cites stay byte-identical, and no
# edge record is published. Repository bytes are read only through reviewed_bytes, and the contract's modes and directory
# listing only through reviewed_mode and reviewed_tree, so a later bridged successor projects its own edits away first; a
# path outside this era is refused before it is read, and every era file is bound by digest on every read. The bindings,
# the change kinds and their rules, the decisions, the packet scope, every file:line citation and the adoption record with
# its candidates and review rounds are restated and checked here, independently of the contract's builder. This layer's
# own inverse hunks are the canonical byte-minimal ones, recomputed from its era's bytes (MET-PERF-040's carried rule).
AM3_DIR = "architecture/w03-obligation-amendment-3/"
AMENDMENT = AM3_DIR + "amendment.json"
README_PATH = AM3_DIR + "README.md"
REVIEW_BRIEF_PATH = AM3_DIR + "REVIEW_BRIEF.md"
STATUS_PATH = AM3_DIR + "status.json"
PLAN_V2 = "architecture/w03-plan-v2/plan.json"
AMENDMENT_1 = "architecture/w03-obligation-amendment-1/amendment.json"
AMENDMENT_2 = "architecture/w03-obligation-amendment-2/amendment.json"
EDGES_DIR = "architecture/artifact-edges/"
V5_EDGE = EDGES_DIR + "operator-harness-engineering-v5.json"
NP4_README = "architecture/native-profile-v4/README.md"
# The reviewed subject in the review records' order, and the adopted candidate 5's bytes as the re-adoption names them.
SUBJECT = (AMENDMENT, README_PATH)
ADOPTED_SHA256 = {AMENDMENT: "ddf5e9abd4c23d4fb09031693466079c68ea2a07c8068a5cdcde0b9bb7d2882b",
                  README_PATH: "1e2092e83133d51a888c3cea237bd97928c7679980a8db3d52075b1c089a78c0"}
BASE_MAIN = "a3b9e6e7aedd68e092f3601aa729b61be7241755"
REVIEW_BASE = "f4bb0000df9ec4bdaac54d3e6488d691e2001f28"
# Every new contract file: the subject, the review brief, the status record, the four review records and the snapshots
# of candidates 1 to 4 (only the files whose bytes differ from the adopted ones).
NEW_FILES = (
    "architecture/w03-obligation-amendment-3/amendment.json",
    "architecture/w03-obligation-amendment-3/README.md",
    "architecture/w03-obligation-amendment-3/REVIEW_BRIEF.md",
    "architecture/w03-obligation-amendment-3/status.json",
    "architecture/w03-obligation-amendment-3/review-round1.json",
    "architecture/w03-obligation-amendment-3/review-round2.json",
    "architecture/w03-obligation-amendment-3/review-round3.json",
    "architecture/w03-obligation-amendment-3/review-round4.json",
    "architecture/w03-obligation-amendment-3/candidate1/architecture/w03-obligation-amendment-3/README.md",
    "architecture/w03-obligation-amendment-3/candidate1/architecture/w03-obligation-amendment-3/amendment.json",
    "architecture/w03-obligation-amendment-3/candidate2/architecture/w03-obligation-amendment-3/README.md",
    "architecture/w03-obligation-amendment-3/candidate2/architecture/w03-obligation-amendment-3/amendment.json",
    "architecture/w03-obligation-amendment-3/candidate3/architecture/w03-obligation-amendment-3/README.md",
    "architecture/w03-obligation-amendment-3/candidate3/architecture/w03-obligation-amendment-3/amendment.json",
    "architecture/w03-obligation-amendment-3/candidate4/architecture/w03-obligation-amendment-3/README.md",
    "architecture/w03-obligation-amendment-3/candidate4/architecture/w03-obligation-amendment-3/amendment.json",
)
# (round, verdict, the candidate it reviewed, its findings) in order; round 4 reviewed candidate 5, the adopted one.
ROUNDS = ((1, "CHANGES_REQUIRED", 1, tuple("C1-%d" % n for n in range(1, 10))),
          (2, "PASS_FOR_ADOPTION", 2, tuple("C2-%d" % n for n in range(1, 5))),
          (3, "PASS_FOR_ADOPTION", 3, ("C3-1", "C3-2")),
          (4, "PASS_FOR_ADOPTION", 5, tuple("C4-%d" % n for n in range(1, 5))))
CANDIDATES = 5
STATUS_KEYS = ("schemaVersion", "workItem", "amendmentId", "status", "adoption", "supersededAdoption", "baseMain",
               "reviewBase", "adoptedSubject", "independentReviewer", "readmeStatusNote", "recordPaths", "candidates",
               "rounds", "closedFindings", "carried", "nonClaims")
CANDIDATE_KEYS = ("candidate", "sha256", "snapshot", "keptCopies")
ROUND_KEYS = ("round", "record", "recordSha256", "verdict", "candidate", "subjectSha256", "snapshot")
# A review record names its subject candidate and that candidate's file digests in its subject line.
SUBJECT_SHA = re.compile(r"candidate ([0-9]) \(amendment\.json sha256 ([0-9a-f]{64}); README\.md ([0-9a-f]{64}); ")
# The lane monitor's re-adoption of candidate 5, and the candidate-4 adoption it superseded with the owner's reason,
# verbatim from the decisions record.
ADOPTION = {'decidedBy': 'the lane monitor, owner-delegated',
 'date': '2026-10-18',
 'candidate': 5,
 'decision': 'Monitor: RE-ADOPT AMEND-3 candidate 5 for slot 250 (amendment.json ddf5e9ab, README 1e2092e8, '
             "build_contract.py 101b795f), on round 4's PASS_FOR_ADOPTION (f38a2b7b), which states the c3→c4→c5 "
             'delta explicitly. NOTEs C4-1..4 are noted, and candidate 5 stays frozen. Record this verbatim and '
             "dated (it supersedes the candidate-4 adoption). Mechanics wait for 249's merge: PR #203's verify is "
             "starting now. I'll give the word after the merge."}
SUPERSEDED = {'candidate': 4,
 'date': '2026-10-18',
 'decision': '"Monitor: ADOPT candidate 4 for slot 250 (amendment.json c013efd9, README b662e6f3, '
             'build_contract.py 8a742132). No round 4. Condition: the packet review must check the c3→c4 diff '
             'explicitly, a single added "source" line on carried[1], verified against native-profile-v4 '
             "README:494, plus the DRAFT-only wording. It must state that nothing else changed since round 3's "
             'PASS (6fba6636).\n'
             "Mechanics (packet build, pre-check, dry run, push) wait for 249's merge and my word. 249's pre-check "
             'is running now. Packet id at mechanics."',
 'why': 'Q-HE4D1-D2 = (a): keep the 60 s cadence (Q-HE4D1-6 (a)); the WORKER attempt goes first in each set, right '
        'after the scrape. NP-9\'s minimum becomes "one observer cycle plus the scrape-to-set bound plus one 2 s '
        'window, plus margin". R10 states the number, and HE-005 keeps how often. The owner accepts the longer '
        'probe-worker freeze.',
 'instruction': 'Record these verbatim and dated. Do AMEND-3 candidate 5: change only the NP-9 minimum text '
                "(HE-005's share, T04's share and the decision quote), then a short delta review r4. Then ask me "
                'to re-adopt; my candidate-4 adoption is superseded by this. D1 rev 2 folds everything else.'}
CLOSED_FINDINGS = {
    **{"C1-%d" % n: "CLOSED in candidate 2 (round 2: FIXED)" for n in range(1, 10)},
    **{"C2-%d" % n: "CLOSED in candidate 3 (round 3: FIXED)" for n in range(1, 5)},
    "C3-1": "APPLIED in candidate 4: carried[1].source names architecture/native-profile-v4/README.md:494 (round 4, "
            "c3ToC4)",
    "C3-2": "APPLIED in candidate 4: DRAFT.md wording only; the DRAFT is not published (round 4, c3ToC4)",
    "C4-1": "KEPT as a builder tripwire: the contract builder still asserts the superseded NP-9 minimum line once and uses "
            "it nowhere; candidate 5 stays frozen (the monitor's re-adoption)",
    "C4-2": "HANDED to the HE-004D1 design: R10's worst-case number (see carried)",
    "C4-3": "HANDED to the HE-004D1 design: the WORKER attempt first in each set (see carried)",
    "C4-4": "DRAFT-only: the DRAFT is not published"}
CARRIED = (("amendment.json carried[0]-[4]", "as each item names"),
           ("C4-3 (contract review round 4, NOTE): the WORKER attempt first in each set, right after the scrape",
            "the HE-004D1 design (revision 2)"),
           ("C4-2 (contract review round 4, NOTE): R10's worst-case number for NP-9's minimum",
            "the HE-004D1 design (revision 2)"))
NON_CLAIMS = ["Plan v2, amendments 1 and 2 and edge record v5 are byte-identical.",
              "No edge record is published in this packet.",
              "No R10 file changes in this packet.",
              "The HE-004D1 design is not part of this packet."]
# The README keeps its reviewed candidate status (readmeStatusNote).
CANDIDATE_STATUS = "Status: **CONTRACT_CANDIDATE_AWAITING_INDEPENDENT_REVIEW**"
# The stated deltas: candidate 4 is candidate 3 plus carried[1].source (C3-1) with the README unchanged; candidate 5 is
# candidate 4 with exactly these four values changed (the NP-9 minimum, owner decision Q-HE4D1-D2 (a)).
C3_TO_C4 = ("carried", 1, "source")
C4_TO_C5 = (("ownerDecisions", 14), ("changes", 1, "source"), ("changes", 1, "shares", "HE-005"),
            ("changes", 1, "shares", "T04"))
SCHEMA = "planeon.internal.w03-obligation-amendment/v3"
AMENDMENT_ID = "W03-PLAN-AMEND-3"
AMENDS_PACKET = "MET-ENFORCE-024"
AFTER = ((AMENDMENT_1, "MET-ENFORCE-025"), (AMENDMENT_2, "MET-ENFORCE-032"))
CHANGE_KINDS = frozenset({"ADDED", "REFINED", "PACKETS_ADDED", "SHARE_CORRECTED"})
CHANGES = (("OBS-HOSTPOL-1", "ADDED"), ("NP-9", "ADDED"), ("SEC-4", "SHARE_CORRECTED"), ("HI-7", "SHARE_CORRECTED"))
CORRECTION_KEYS = ("path", "sha256", "rowLines", "shareLine", "share")
OWNER_DECISIONS = 17
# A decision id as the records write it (Q-HE4D1-D2, Q-HE4-3/4, Q-A3-7), and a list of one family's numbers written once
# ("Q-HE4D1-2, 3, 5 ... and 12", "Q-HE4D1-8 and -9").
DECISION_ID = re.compile(r"\bQ-[A-Z0-9]+(?:-[A-Z0-9]+)*(?:/[0-9]+)?")
DECISION_LIST = re.compile(r"\b(Q-[A-Z0-9]+(?:-[A-Z0-9]+)*-)([0-9]+)((?:,? (?:and )?-?[0-9]+\b)+)")
# A decision an earlier contract records, cited by its lines there rather than quoted in ownerDecisions.
RECORDED_ELSEWHERE = {"Q-NP4D-10": (NP4_README, 302, 303)}
REFINED_PACKET = "HE-004"
SCOPE_KEYS = ("packet", "partOf", "where", "summaryIn", "obligations", "scope", "np3Route", "dossier", "decisions",
              "handOffs", "residuals")
HAND_OFF_KEYS = ("item", "to", "decision")
PACKET_ID = re.compile(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+")
SUMMARY_IN = re.compile(r"([a-z0-9/._-]+\.json):([0-9]+)-([0-9]+)")
# A file:line citation: a repository path then :line or :from-to; a bare :line or :from-to cites the last path named in
# full earlier in the same text.
CITATION = re.compile(r"(?<![\w./-])((?:architecture|docs)/[A-Za-z0-9._/-]+?\.(?:json|md|yaml))?:([0-9]+)(?:-([0-9]+))?"
                      r"(?![\w-])")
CITED_RANGES = 44
DEVICE_INODE = (NP4_README, 494, "with the device and inode observed for that file")
# Absolute local paths a published record must not hold (assembled so this file holds none); a bare prefix such as
# "/private/tmp," in a privacy statement is not a path.
LOCAL_PATHS = (re.compile(rb"/Us" rb"ers/[^/\s,'\"]+/"), re.compile(rb"/pri" rb"vate/tmp/[^\s,'\"]"))
# Plan v2, amendments 1 and 2 and the edge records: no file changed or added; no edge record is published.
FROZEN_DIRS = ("architecture/w03-plan-v2/", "architecture/w03-obligation-amendment-1/",
               "architecture/w03-obligation-amendment-2/", EDGES_DIR)
# Plan v2, amendments 1 and 2 (with amendment 2's status record), edge record v5 and every other file the amendment cites.
FROZEN_PATHS = (
    "architecture/artifact-edges/operator-harness-engineering-v5.json",
    "architecture/compiled-filter-programs/status.json",
    "architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md",
    "architecture/native-profile-v4/README.md",
    "architecture/native-profile-v4/qualification.schema.json",
    "architecture/native-profile-v4/status.json",
    "architecture/selinux-matrix-v3/README.md",
    "architecture/selinux-matrix-v3/matrix.json",
    "architecture/selinux-matrix-v4/README.md",
    "architecture/w03-obligation-amendment-1/amendment.json",
    "architecture/w03-obligation-amendment-2/amendment.json",
    "architecture/w03-obligation-amendment-2/status.json",
    "architecture/w03-plan-v2/plan.json",
    "docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md",
)
ERA_SHA256 = MappingProxyType({
    "architecture/artifact-edges/operator-harness-engineering-v5.json": "89b47ef8f865b31911eb8da2b08a5a3c22b2d92a62599cb6fdfccbfe7f79e3c0",
    "architecture/compiled-filter-programs/status.json": "f2af6196ea28cebda5530e0792f7cadceb004f8aec01f2857a49823a845ac6c1",
    "architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md": "b4f46b3a79c45691d7029a79849a555aca5ca7a6e6c600958147935f806888e9",
    "architecture/native-profile-v4/README.md": "a4205a5388dc83827bb39670bcc9477b030f29829128abf19f7578321c170174",
    "architecture/native-profile-v4/qualification.schema.json": "c3e91c087ebc6a13e8a96a066f80710ac968c8def434d1d1b97415811715ed10",
    "architecture/native-profile-v4/status.json": "b998d1151cfe7fada1d4e30829064ceaad5d9c1220f407c6c865bc47c197143c",
    "architecture/selinux-matrix-v3/README.md": "0070f3b5be1d68eb6d1e76e9aceed496b5c1ecce91f8cd3b69c81ffdee1e9167",
    "architecture/selinux-matrix-v3/matrix.json": "01e4f3cfd75250dc6fd74f666cfa53758f83b7a07d7a39a0ca180f5588496b73",
    "architecture/selinux-matrix-v4/README.md": "70c537948532496737ec6228306db015f2c93b6df4bdeb0c476d3481b1861c40",
    "architecture/w03-obligation-amendment-1/amendment.json": "2a98e28989f41d69b27a580db8113e56d5adc1fcc1a4b96517997ce7b01f4bd2",
    "architecture/w03-obligation-amendment-2/amendment.json": "a1d861866136a52c378777ab4bb974df856cccf147551b0dab8c4fad8f234f0b",
    "architecture/w03-obligation-amendment-2/status.json": "caf4cf34f8b4dbb995b47efc97688f235634cf9850e817f8c936cc9dce8491b5",
    "architecture/w03-obligation-amendment-3/README.md": "1e2092e83133d51a888c3cea237bd97928c7679980a8db3d52075b1c089a78c0",
    "architecture/w03-obligation-amendment-3/REVIEW_BRIEF.md": "c47f565ae5b82a3843812e36041f9a36549696170c749357578eba99e3513bec",
    "architecture/w03-obligation-amendment-3/amendment.json": "ddf5e9abd4c23d4fb09031693466079c68ea2a07c8068a5cdcde0b9bb7d2882b",
    "architecture/w03-obligation-amendment-3/candidate1/architecture/w03-obligation-amendment-3/README.md": "6e8831a011d6d9ac2c973e13e16cc2a28de833f0b2bf23055785de20d54f6474",
    "architecture/w03-obligation-amendment-3/candidate1/architecture/w03-obligation-amendment-3/amendment.json": "e8aafd081e65976b71368f2e757aa654fbd1f5f9d714f01ba8c42a9e8a3e22a5",
    "architecture/w03-obligation-amendment-3/candidate2/architecture/w03-obligation-amendment-3/README.md": "b7312dfab2220454fdc3c7d9d395671606fb40c9fcf5169cfaf915f1ccb914a1",
    "architecture/w03-obligation-amendment-3/candidate2/architecture/w03-obligation-amendment-3/amendment.json": "5454deca5af15b6cf2a1b42580ed8eaecbe7c8576f7b814e0df8d904e00a3974",
    "architecture/w03-obligation-amendment-3/candidate3/architecture/w03-obligation-amendment-3/README.md": "b662e6f36f1409486961370e7ac7662c578e881c69b16c369a98732862ceef13",
    "architecture/w03-obligation-amendment-3/candidate3/architecture/w03-obligation-amendment-3/amendment.json": "0876f9b29c9431b5ff5a3e9f516067e3a7a9d855f253f63d24fe408d1a4f77b1",
    "architecture/w03-obligation-amendment-3/candidate4/architecture/w03-obligation-amendment-3/README.md": "b662e6f36f1409486961370e7ac7662c578e881c69b16c369a98732862ceef13",
    "architecture/w03-obligation-amendment-3/candidate4/architecture/w03-obligation-amendment-3/amendment.json": "c013efd9725636830a29c71c2bd61ad2ad7dd5e1262a73475cd50a4370e16416",
    "architecture/w03-obligation-amendment-3/review-round1.json": "126af92049598048b7375ee5959eb2ecbf26e3512c9f16a10a57a9c1ee120519",
    "architecture/w03-obligation-amendment-3/review-round2.json": "df49466e204b3dbc1c8d5ba0e2109473b6394290d57c7c6a3282dfc00cf14ed1",
    "architecture/w03-obligation-amendment-3/review-round3.json": "6fba6636847758910c19c8c817c5b1e2451b814c551ad4125b7f50e578563991",
    "architecture/w03-obligation-amendment-3/review-round4.json": "f38a2b7b33d1fe3ed9432066792e1713608c6068d29f4da0abf5640e8d471eb2",
    "architecture/w03-obligation-amendment-3/status.json": "d9e266b483b0774596cb585352a38f7173016c1b223a2c00766d1ba367fd057a",
    "architecture/w03-plan-v2/plan.json": "a00470238431347da82cc47b1f1b6cf7cd51042d56694eea68d1373a3aaefb67",
    "docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md": "60bed4c5358527dabfba15bf4e7a7f584872715ef2ca4f9b4350303b656bf595",
})


def _parents(paths: tuple) -> set:
    folders = set()
    for path in paths:
        parts = path[len(AM3_DIR):].split("/")[:-1]
        folders |= {AM3_DIR + "/".join(parts[:end]) for end in range(1, len(parts) + 1)}
    return folders


CONTRACT_TREE = frozenset(set(NEW_FILES) | _parents(NEW_FILES))


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


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-ENFORCE-037 reviewed bytes are bound: " + str(path))
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed W03-PLAN-AMEND-3 source: " + path)
    return raw


def _json(path: str) -> Any:
    return parse(_verified(path))


def _lines(path: str) -> list:
    """The lines of an era file, numbered from 1 by their index plus one; a final newline ends the last line."""
    lines = _verified(path).decode("utf-8").split("\n")
    return lines[:-1] if lines[-1] == "" else lines


def _holds(check: Any) -> bool:
    """A structural check over this era's data; a malformed value does not hold."""
    try:
        return check() is True
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        return False


def _bound(check: Any, message: str) -> None:
    require(_holds(check), message)


def _texts(values: Any) -> bool:
    return type(values) is list and len(values) > 0 and all(type(text) is str and text.strip() != "" for text in values)


def local_paths(raw: bytes) -> list:
    """The absolute local path patterns raw matches."""
    return [pattern.pattern for pattern in LOCAL_PATHS if pattern.search(raw)]


def _strings(value: Any) -> list:
    """Every string in a parsed record, in document order."""
    if type(value) is str:
        return [value]
    if type(value) is list:
        return [text for item in value for text in _strings(item)]
    if type(value) is dict:
        return [text for item in value.values() for text in _strings(item)]
    return []


def citations(value: Any) -> list:
    """Every file:line citation in a parsed record as (path, first, last); a bare range takes the last full path of its
    text, and one with none is (None, first, last)."""
    cited = []
    for text in _strings(value):
        last = None
        for match in CITATION.finditer(text):
            last = match.group(1) or last
            first = int(match.group(2))
            cited.append((last, first, int(match.group(3) or first)))
    return cited


def decision_ids(text: str) -> set:
    """The decision ids a text names, a list of one family's numbers included."""
    names = set(DECISION_ID.findall(text))
    for family, first, rest in DECISION_LIST.findall(text):
        names |= {family + number for number in [first] + re.findall(r"[0-9]+", rest)}
    return names


def _has_lines(path: str, first: int, last: int) -> bool:
    return type(first) is int and type(last) is int and 1 <= first <= last <= len(_lines(path))


def _value(record: Any, key_path: tuple) -> Any:
    for key in key_path:
        record = record[key]
    return record


def _registers() -> tuple[dict, set]:
    """Each obligation's packet list after amendment 2 (plan v2, then amendment 1, then amendment 2) and every obligation
    id those three name."""
    plan, first, second = _json(PLAN_V2), _json(AMENDMENT_1), _json(AMENDMENT_2)
    lists = {row["id"]: list(row["packets"]) for row in plan["obligations"]}
    known = set(lists)
    for record in (first, second):
        for row in record["changes"]:
            known.add(row["obligation"])
            if "packets" in row:
                lists[row["obligation"]] = list(row["packets"])
    return lists, known


def validate_contract_files() -> None:
    """No frozen file is changed or added and no edge record is published; the contract's files are new here, each once;
    the contract directory holds exactly its files and the candidate snapshots; every contract file is a regular file of
    git mode 100644, not a symlink and not executable; and none holds an absolute local path."""
    new = authority()["newFiles"]
    for path in list(_PROJECTION_RULES) + list(new):
        require(path not in FROZEN_PATHS and not path.startswith(FROZEN_DIRS),
                "plan v2, amendments 1 and 2, the edge records and the cited files stay byte-identical")
    require(len(set(NEW_FILES)) == len(NEW_FILES) and {path for path in new if path.startswith(AM3_DIR)} == set(NEW_FILES),
            "the contract's files are new in this packet, each once")
    require(stat.S_ISDIR(reviewed_mode(AM3_DIR[:-1])), "the contract directory is a directory, not a link")
    tree = reviewed_tree(AM3_DIR)
    require(set(tree) == CONTRACT_TREE and all(stat.S_ISDIR(tree[path]) for path in CONTRACT_TREE - set(NEW_FILES)),
            "the contract directory holds exactly its files and the candidate snapshots")
    for path in NEW_FILES:
        mode = tree[path]
        require(stat.S_ISREG(mode) and not mode & 0o111, "a contract file is a regular file of git mode 100644: " + path)
        require(not local_paths(_verified(path)), "no absolute local path in a contract file: " + path)


def validate_amendment_3_status() -> None:
    """Re-adopted after four independent review rounds, each bound to its record and its subject candidate's exact bytes;
    the five candidates are bound to their snapshots; the adopted files are candidate 5; candidate 4 is candidate 3 plus
    C3-1's source and candidate 5 is candidate 4 with only the NP-9 minimum's four values changed."""
    status = _json(STATUS_PATH)
    _bound(lambda: type(status) is dict and tuple(status) == STATUS_KEYS
           and status["schemaVersion"] == "planeon.internal.w03-obligation-amendment-3-status/v1"
           and status["workItem"] == status["amendmentId"] == AMENDMENT_ID and status["status"] == "ADOPTED"
           and status["adoption"] == ADOPTION and status["supersededAdoption"] == SUPERSEDED
           and status["baseMain"] == BASE_MAIN and status["reviewBase"] == REVIEW_BASE
           and status["adoptedSubject"] == ADOPTED_SHA256 and tuple(status["adoptedSubject"]) == SUBJECT
           and status["independentReviewer"] == "SEPARATE_AGENT_NOT_AUTHOR"
           and all(type(status[key]) is str and status[key] != "" for key in ("readmeStatusNote", "recordPaths"))
           and status["closedFindings"] == CLOSED_FINDINGS and tuple(status["closedFindings"]) == tuple(CLOSED_FINDINGS)
           and status["nonClaims"] == NON_CLAIMS and type(status["carried"]) is list
           and all(type(row) is dict and tuple(row) == ("item", "to", "action") and type(row["action"]) is str
                   and row["action"] != "" for row in status["carried"])
           and [(row["item"], row["to"]) for row in status["carried"]] == list(CARRIED),
           "adopted W03-PLAN-AMEND-3 status")
    for path in SUBJECT:
        require(digest(_verified(path)) == ADOPTED_SHA256[path], "the adopted files are candidate 5: " + path)
    candidates = status["candidates"]
    _bound(lambda: type(candidates) is list and len(candidates) == CANDIDATES
           and all(type(row) is dict and tuple(row) == CANDIDATE_KEYS for row in candidates)
           and [row["candidate"] for row in candidates] == list(range(1, CANDIDATES + 1)),
           "five candidates in order")
    for number, row in enumerate(candidates, 1):
        snapshot, kept = row["snapshot"], row["keptCopies"]
        _bound(lambda: type(row["sha256"]) is dict and tuple(row["sha256"]) == SUBJECT
               and type(kept) is list and len(set(kept)) == len(kept) and set(kept) <= set(SUBJECT)
               and (snapshot == AM3_DIR + "candidate%d/" % number if number < CANDIDATES else snapshot is None and kept == [])
               and all((path in kept) == (row["sha256"][path] != ADOPTED_SHA256[path]) for path in SUBJECT)
               and all(digest(_verified(snapshot + path if path in kept else path)) == row["sha256"][path]
                       for path in SUBJECT),
               "candidate %d is bound to its snapshot and its exact bytes" % number)
    rounds = status["rounds"]
    _bound(lambda: type(rounds) is list and len(rounds) == len(ROUNDS)
           and all(type(row) is dict and tuple(row) == ROUND_KEYS for row in rounds)
           and [(row["round"], row["verdict"], row["candidate"]) for row in rounds]
           == [(number, verdict, candidate) for number, verdict, candidate, _findings in ROUNDS],
           "four review rounds in order, the last on the adopted candidate 5")
    for (number, verdict, candidate, findings), row in zip(ROUNDS, rounds):
        subject = candidates[candidate - 1]
        record = _json(row["record"]) if row["record"] == AM3_DIR + "review-round%d.json" % number else None

        def bound() -> bool:
            named = SUBJECT_SHA.search(record["subject"])
            return (type(record) is dict and digest(_verified(row["record"])) == row["recordSha256"]
                    and record["round"] == number and record["verdict"] == verdict
                    and named is not None and int(named.group(1)) == candidate
                    and {AMENDMENT: named.group(2), README_PATH: named.group(3)} == subject["sha256"]
                    and row["subjectSha256"] == subject["sha256"] and row["snapshot"] == subject["snapshot"]
                    and tuple(finding["id"] for finding in record["findings"]) == findings
                    and record["actions"] == {"filesEdited": False, "networkAccessed": "none", "personalDataSent": False})
        _bound(bound, "review round %d is bound to its record and its subject candidate's exact bytes" % number)
        if number in (2, 3):
            previous = ROUNDS[number - 2][3]
            _bound(lambda: [(prior["id"], prior["status"]) for prior in record["priorFindings"]]
                   == [(name, "FIXED") for name in previous],
                   "review round %d fixed every finding of round %d" % (number, number - 1))
    _bound(lambda: all(type(_json(rounds[3]["record"])["changesSinceRound3"][key]) is str
                       for key in ("round3Record", "c3ToC4", "c4ToC5")),
           "round 4 states the c3->c4->c5 delta")
    third = candidates[2]["snapshot"]
    fourth = candidates[3]["snapshot"]

    def delta() -> bool:
        candidate3, candidate4, adopted = _json(third + AMENDMENT), _json(fourth + AMENDMENT), _json(AMENDMENT)
        added = copy.deepcopy(candidate3)
        _value(added, C3_TO_C4[:-1])[C3_TO_C4[-1]] = _value(candidate4, C3_TO_C4)
        changed = copy.deepcopy(candidate4)
        for key_path in C4_TO_C5:
            require(_value(candidate4, key_path) != _value(adopted, key_path), "a stated change changes a value")
            _value(changed, key_path[:-1])[key_path[-1]] = _value(adopted, key_path)
        return (C3_TO_C4[-1] not in _value(candidate3, C3_TO_C4[:-1]) and added == candidate4
                and _value(candidate4, C3_TO_C4) == "%s:%d" % DEVICE_INODE[:2]
                and _verified(third + README_PATH) == _verified(fourth + README_PATH) and changed == adopted)
    _bound(delta, "candidate 5 is candidate 3 with only the stated c3->c4->c5 delta")
    text = _verified(README_PATH).decode("utf-8")
    require(text.count("Status: **") == 1 and text.count(CANDIDATE_STATUS) == 1,
            "the README keeps its reviewed candidate status line")


def _corrects(row: dict, record: dict, lists: dict, corrected: dict) -> bool:
    """One SHARE_CORRECTED row, as the amendment's correctionRule states it."""
    corrects, name, packet = row["corrects"], row["obligation"], row["packet"]
    if type(corrects) is not dict or tuple(corrects) != CORRECTION_KEYS:
        return False
    entries = [number for number, entry in enumerate(record["after"], 1)
               if (entry["path"], entry["sha256"]) == (corrects["path"], corrects["sha256"])]
    span = re.fullmatch(r"([0-9]+)-([0-9]+)", corrects["rowLines"])
    if len(entries) != 1 or span is None or type(corrects["shareLine"]) is not int:
        return False
    first, last, at = int(span.group(1)), int(span.group(2)), corrects["shareLine"]
    if not (_has_lines(corrects["path"], first, last) and first <= at <= last):
        return False
    lines = _lines(corrects["path"])
    block = "\n".join(lines[first - 1:last]).rstrip()
    earlier = _json(corrects["path"])
    shown = parse((block[:-1] if block.endswith(",") else block).encode("utf-8"))
    line = lines[at - 1].strip()
    share_line = parse(("{" + (line[:-1] if line.endswith(",") else line) + "}").encode("utf-8"))
    if not (type(shown) is dict and earlier["changes"].count(shown) == 1 and shown["obligation"] == name
            and share_line == {packet: shown["shares"][packet]}
            and corrects["share"] == "%s's share in amendment %d's %s %s row" % (packet, entries[0], name, shown["change"])):
        return False
    share, replaced, replacement = corrected.get((name, packet), shown["shares"][packet]), row["replaced"], row["replacement"]
    holds = (type(replaced) is str and type(replacement) is str and replaced != "" and share.count(replaced) == 1
             and row["shares"] == {packet: share.replace(replaced, replacement)}
             and row["packets"] == lists[name] and packet in row["packets"])
    if holds:
        corrected[(name, packet)] = row["shares"][packet]
    return holds


def validate_amendment() -> None:
    """The bindings, the closed change kinds and their rules over plan v2 and amendments 1 and 2 as this era holds them:
    ADDED rows add obligations absent from all three, with packets and shares for listed packets; SHARE_CORRECTED rows
    correct one located share of a bound amendment, in order, with the list after amendment 2 unchanged; and the
    decisions are recorded."""
    record = _json(AMENDMENT)
    _bound(lambda: record["schemaVersion"] == SCHEMA and record["id"] == AMENDMENT_ID
           and record["amends"] == {"path": PLAN_V2, "sha256": "sha256:" + digest(_verified(PLAN_V2)),
                                    "packet": AMENDS_PACKET}
           and type(record["after"]) is list
           and record["after"] == [{"path": path, "sha256": "sha256:" + digest(_verified(path)), "packet": packet}
                                   for path, packet in AFTER],
           "the amendment binds plan v2 and amendments 1 and 2, in order, by their bytes")
    _bound(lambda: type(record["changeKinds"]) is dict and set(record["changeKinds"]) == CHANGE_KINDS
           and all(type(text) is str and text != "" for text in record["changeKinds"].values())
           and type(record["changes"]) is list and len(record["changes"]) > 0
           and all(type(row) is dict and row["change"] in record["changeKinds"] for row in record["changes"]),
           "the closed change kinds")
    _bound(lambda: [(row["obligation"], row["change"]) for row in record["changes"]] == list(CHANGES),
           "the amendment's four changes, in order")
    lists, known = _registers()
    corrected: dict = {}
    for row in record["changes"]:
        name, kind = row["obligation"], row["change"]
        if kind == "ADDED":
            _bound(lambda: name not in known and type(row["text"]) is str and row["text"].strip() != ""
                   and _texts(row["packets"]) and len(set(row["packets"])) == len(row["packets"]),
                   "an ADDED row adds an obligation absent from plan v2 and amendments 1 and 2: " + name)
            known.add(name)
        else:
            _bound(lambda: _corrects(row, record, lists, corrected),
                   "a SHARE_CORRECTED row corrects one located share of a bound amendment as quoted: " + name)
        _bound(lambda: type(row["source"]) is str and row["source"] != ""
               and type(row["shares"]) is dict and len(row["shares"]) > 0 and set(row["shares"]) <= set(row["packets"])
               and _texts(list(row["shares"].values())),
               "every share names a packet in its row's list: " + name)
        lists[name] = list(row["packets"])
    decisions = record["ownerDecisions"]
    _bound(lambda: _texts(decisions) and len(decisions) == OWNER_DECISIONS and len(set(decisions)) == OWNER_DECISIONS,
           "the 17 recorded decisions are unique non-empty texts")
    decided = {name for text in decisions for name in decision_ids(text)}

    def cited() -> set:
        names = {name for row in record["changes"] for name in DECISION_ID.findall(row["source"])}
        for scope in record["packetScopes"]:
            names |= {row["id"] for row in scope["decisions"]}
            names |= {name for row in scope["handOffs"] for name in DECISION_ID.findall(row["decision"])}
        return names | {name for row in record["carried"] for name in DECISION_ID.findall(row["decision"])}
    _bound(lambda: all(name in decided or (name in RECORDED_ELSEWHERE and name in "\n".join(
                       _lines(RECORDED_ELSEWHERE[name][0])[RECORDED_ELSEWHERE[name][1] - 1:RECORDED_ELSEWHERE[name][2]]))
                       for name in cited()),
           "every decision a change, scope, hand-off or carried item cites is recorded")


def validate_packet_scopes() -> None:
    """Each packet scope is a part of amendment 2's HE-004, named in its obligations' lists after this amendment, with
    amendment 2's summary lines, its decisions, hand-offs that name a packet and a decision, and its residuals."""
    record, second = _json(AMENDMENT), _json(AMENDMENT_2)
    lists, _known = _registers()
    for row in record["changes"]:
        lists[row["obligation"]] = list(row["packets"])
    refinements = {row["packet"]: row for row in second["packetRefinements"]}
    parts = [part["id"] for part in refinements[REFINED_PACKET]["parts"]]
    scopes = record["packetScopes"]
    _bound(lambda: type(scopes) is list and len(scopes) > 0, "the packet scopes")
    for scope in scopes:
        packet = scope["packet"]
        _bound(lambda: type(scope) is dict and tuple(scope) == SCOPE_KEYS and packet in parts
               and scope["partOf"] == REFINED_PACKET,
               "a packet scope is a part of amendment 2's HE-004: " + str(packet))
        _bound(lambda: _texts(scope["obligations"]) and all(packet in lists[name] for name in scope["obligations"]),
               "each scoped obligation names the part after this amendment: " + packet)

        def summary() -> bool:
            where = SUMMARY_IN.fullmatch(scope["summaryIn"])
            first, last = int(where.group(2)), int(where.group(3))
            lines = _lines(AMENDMENT_2)
            return (where.group(1) == AMENDMENT_2 and _has_lines(AMENDMENT_2, first, last)
                    and lines[first - 1].strip() == '"id": "%s",' % packet
                    and lines[last - 1].strip().startswith('"summary": '))
        _bound(summary, "the scope's summaryIn is the part's lines in amendment 2: " + packet)
        _bound(lambda: type(scope["decisions"]) is list and len(scope["decisions"]) > 0
               and all(type(row) is dict and all(type(row[key]) is str and row[key] != ""
                                                 for key in ("id", "question", "selected", "option"))
                       for row in scope["decisions"])
               and len({row["id"] for row in scope["decisions"]}) == len(scope["decisions"]),
               "the scope's decisions are named once each: " + packet)
        _bound(lambda: type(scope["handOffs"]) is list
               and all(type(row) is dict and tuple(row) == HAND_OFF_KEYS and type(row["item"]) is str
                       and row["item"] != "" and PACKET_ID.fullmatch(row["to"]) is not None
                       and DECISION_ID.search(row["decision"]) is not None for row in scope["handOffs"]),
               "every hand-off names a packet and a decision: " + packet)
        _bound(lambda: _texts(scope["residuals"]), "the scope's residuals: " + packet)


def validate_citations() -> None:
    """Every file:line citation in the amendment resolves at the base: a frozen file of this era with those lines; and
    carried[1] cites native-profile v4's device-and-inode rule."""
    record = _json(AMENDMENT)
    cited = citations(record)
    _bound(lambda: len(set(cited)) == CITED_RANGES
           and all(path in FROZEN_PATHS and _has_lines(path, first, last) for path, first, last in cited),
           "every file:line citation in the amendment resolves at the base")
    path, line, rule = DEVICE_INODE
    _bound(lambda: record["carried"][1]["source"] == "%s:%d" % (path, line) and rule in _lines(path)[line - 1],
           "carried[1] cites native-profile v4's device-and-inode rule")


def validate_w03_plan_amend_3() -> None:
    """Every reviewed byte first; then the contract's files, the adoption record, the amendment's rules, the packet
    scope and the citations; last, this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_contract_files()
    validate_amendment_3_status()
    validate_amendment()
    validate_packet_scopes()
    validate_citations()
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
            == record["validatorNormalizedSha256"], "w03 plan amendment 3 validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 259
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 259-packet catalog retaining the 250-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only w03-plan-amend-3 packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted w03-plan-amend-3 packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_w03_plan_amend_3()


if __name__ == "__main__":
    validate()
    print("W03 obligation-register amendment 3 valid: 259 current specifications; 250-packet checkpoint and exact 249-packet predecessor; contract reviewed.")
