#!/usr/bin/env python3
"""Validate the MET-PERF-041 pytest-diagnostics caps under the 32 MiB output ceiling and the exact 253-to-252 projection."""
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
    import validate_i06_backend_profile_v4 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_i06_backend_profile_v4 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/diagnostic-caps-authority.json"
AUTHORITY_SHA256 = "819b038d6efc8f4bef84d38ee216386ed3e233abbd444e8b0c48ce96bd77c1cb"
VALIDATOR_PATH = "scripts/validate_diagnostic_caps.py"
BASE_COMMIT = "27c54605a3dcdbe86522a6bd18a5e19faa5cb40b"
NEW_PACKET = "MET-PERF-041"
PREVIOUS_PACKET = "MET-ENFORCE-038"
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
            require(key not in result, "duplicate diagnostic-caps authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite diagnostic-caps authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "diagnostic caps history authority digest")
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
    }, "closed diagnostic caps history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/diagnostic-caps-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 252
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 252-packet base")
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
    # An exact 252-era byte string is already older than the successor layer.
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


# MET-PERF-041 (owner decisions Q-253-DIAG (a) and Q-DIAGCAP-SIZE (A), 2026-10-20, via the lane monitor; plan revision 3,
# PASS_FOR_BUILD in contract review round 3) raises the pytest-diagnostics caps in ci/pytest_diagnostics.py under the
# owner's verifier's 32 MiB output ceiling (verify_pr.py:79, enforced at :558, unchanged): MAX_PROCESS_BYTES 20 -> 30
# MiB, MAX_EVENTS 100,000 -> 140,000 and MAX_SCAN_LINES 110,000 -> 154,000, now derived in code as MAX_EVENTS +
# MAX_EVENTS // 10, with MAX_SCAN_BYTES still MAX_PROCESS_BYTES + 1 MiB and 2 MiB reserved for every other output; the
# live digest pin in tests/test_diagnostic_repair.py (line 133) follows. Repository bytes are read only through
# reviewed_bytes, and the contract directory's listing and modes only through reviewed_tree and reviewed_mode, so a
# later bridged successor projects its own edits away first; a path outside this era is refused before it is read, and
# every era file is bound by digest on every read. Checked (PLAN.md section 8): the contract's files and the limits
# record, equal to its restatement here, with the owner decisions verbatim; the three constants and the derived scan
# limits against limits.json's "after" values and the base module's against its "before" values; nothing else in the
# module differs from 27c5460, by canonical hunk; the live pin, whose reverse hunk spans line 133 only (line 132
# untouched, C3-2); the ceiling, the reserve and MAX_PROCESS_BYTES + reserve <= 32 MiB; every historical record
# (MET-PERF-028.yaml's five sentences byte-exact, MET-PERF-028's and MET-PERF-038's pins, reached through this layer's
# reverse hunks); and the recorded executed outcomes against the boundary table, the measurement and the headroom.
# Executed once each from this era's bytes, with a counting sink, at full size: profile W at its last passing count
# completes and one test later fails with OUTPUT_LIMIT and exit 1; profile S likewise with EVENT_LIMIT; summarize_nested
# reports COMPLETE on a stream of exactly MAX_SCAN_BYTES and MAX_SCAN_LINES, INPUT_LIMIT one byte past and SCAN_LIMIT one
# line past; and the base module (27c5460's bytes, through this layer's own inverse) fails profile R at the incident's
# 16,306 tests with OUTPUT_LIMIT. This layer's own inverse hunks are the canonical byte-minimal ones, recomputed from
# its era's bytes (MET-PERF-040's carried rule).
DIAGNOSTICS = "ci/pytest_diagnostics.py"
REPAIR_TEST = "tests/test_diagnostic_repair.py"
ORACLE_TEST = "tests/test_pytest_diagnostics.py"
CAPS_DIR = "architecture/diagnostic-caps/"
CAPS_README = CAPS_DIR + "README.md"
LIMITS_RECORD = CAPS_DIR + "limits.json"
NEW_FILES = (CAPS_README, LIMITS_RECORD)
CONTRACT_TREE = frozenset(NEW_FILES)
PERF_028_PACKET = "task-packets/MET-PERF-028.yaml"
PERF_028_AUTHORITY = "architecture/packet-schema-performance-authority.json"
PERF_038_AUTHORITY = "architecture/load-deadlines-authority.json"
PERF_038_VALIDATOR = "scripts/validate_load_deadlines.py"
PERF_038_RECORDS = ("architecture/load-deadlines/limits.json", "architecture/load-deadlines/README.md")
HISTORICAL_RECORDS = (PERF_028_PACKET, PERF_028_AUTHORITY, PERF_038_AUTHORITY) + PERF_038_RECORDS
ERA_SHA256 = MappingProxyType({
    "architecture/diagnostic-caps/README.md": "8216ec1b3e12bbce15fead83884517251db77d3034ee63e7a92c24591f4af4bf",
    "architecture/diagnostic-caps/limits.json": "5b95b1a42bc15a4de3a8f74e7520ee09da94a15ddd00ef2e8da2c738ca4f0a2c",
    "architecture/load-deadlines-authority.json": "f36e25091fc2c440935d0f8ae5f0687acce9998f30dff5a7cf8327b0a89ce0ab",
    "architecture/load-deadlines/README.md": "36ee4dd227603e6ebef164a20555c30fabfbd59c0c0dbbd2526579478dcb81c1",
    "architecture/load-deadlines/limits.json": "f9c152fd4b7e074e5b63b1649e35e2cc2c651060c1ae48d91c078b8690f0f11f",
    "architecture/packet-schema-performance-authority.json": "b22765d800ef757891addcd308570efeefaca1637b806fd28008a800c0cdff4f",
    "ci/pytest_diagnostics.py": "ac9e70395413356f6348180c0c61a7adec57999f770feed59967b6eac7167745",
    "scripts/validate_load_deadlines.py": "2b7b181ce6e8b50cc218cbcc6ca6ef126eb907b34adaa11f99e4ce3e86041393",
    "task-packets/MET-PERF-028.yaml": "cfa07a1e6d738a0b4ddf531530cba686d0d6c7931e68623c86a63dcdb0e29722",
    "tests/test_diagnostic_repair.py": "68fca6b738e11fff0afb371c7e6dc7893ed315dcaabe34fbb148e4f1d22b8c7d",
    "tests/test_pytest_diagnostics.py": "360eeedef1325728534615a6171780c71a4d0d8c4a0f8fff03f27a66aed1b600",
})
# 27c5460's module, its repair test (MET-PERF-038's era bytes) and MET-PERF-028's repair test, by digest.
BASE_DIAGNOSTICS_SHA256 = "67416db359a8d5953b469e33b92f0b29f3377fdd6daff7fe1a2958e8bc503a23"
BASE_REPAIR_SHA256 = "7b666bb8bab73ea37037292a53e8f7029f1a9128e0d6379dd75533f2b5e558a2"
PERF_028_REPAIR_SHA256 = "89aaa588c5d130021faa51d90697a09015e34f1038bd85efc1ed9d6d9979f181"
# The canonical byte-minimal reverse hunks (at, removed, inserted) of the module (its three cap lines) and of the repair
# test (line 133's digest), restated.
DIAGNOSTICS_HUNKS = ((475, b'3', b'2'), (506, b'4', b'0'), (603, b'MAX_EVENTS + MAX_EVENTS // 1', b'110_00'))
REPAIR_HUNKS = ((5526,
  b'ac9e70395413356f6348180c0c61a7adec57999f770feed59967b6eac7167745',
  b'67416db359a8d5953b469e33b92f0b29f3377fdd6daff7fe1a2958e8bc503a23'),)
LIVE_PIN_LINE, UNCHANGED_PIN_LINE = 133, 132
UNCHANGED_PIN = (b'        "tests/linux_runner/test_predecessor_diagnostics.py": '
                 b'"3c0afe5686f0c39cea2f68d97f50549d0faba890539c3e20aae1d88b2305139f",')
OUTPUT_CEILING_BYTES = 32 * 1024 * 1024
RESERVE_BYTES = 2 * 1024 * 1024
FIVE_SENTENCES = (
    b"Fixed added-diagnostic ceilings are20MiB/process,1024bytes/record,100000records",
    b"Existing32MiB outer ceiling stays unchanged",
    b"do not echo up to20MiB of metadata through pytest traceback",
    b"Keep nested420/local750/trusted900/workflow15min,32MiB outer output ceiling, both full replays and all inherited skips",
    b"Keep all53 commands,420/750/900s,15-minute and32MiB limits")
CAP_NAMES = ("MAX_PROCESS_BYTES", "MAX_EVENTS", "MAX_SCAN_LINES", "MAX_SCAN_BYTES")
KEPT_NAMES = ("MAX_RECORD_BYTES", "MAX_NODE_CHARS", "MAX_FAILURES")
LOCAL_PATH_MARKERS = (b"/" + b"users/", b"/" + b"private/", b".local" + b"/state")
OWNER_DECISIONS = [{'id': 'Q-253-DIAG',
  'selected': 'a',
  'date': '2026-10-20',
  'decision': '(a) ci/ cap packet first (Recommended)',
  'relayed': ['Monitor: owner decision Q-253-DIAG (2026-10-20, via the lane monitor), verbatim: "(a) ci/ cap '
              'packet first (Recommended)". Record it verbatim and dated.',
              '',
              'What that means:',
              '- A small ci/ packet takes harness-onion slot 253, before I06-RBAC-V4. It raises the diagnostics '
              'caps in ci/pytest_diagnostics.py (bytes, events and the derived scan limits) and updates its bound '
              "tests and pins, with tests/test_diagnostic_repair.py's digest of the file as one of them. Follow "
              "MET-PERF-038's precedent.",
              '- MET-ENFORCE-039 moves to slot 254. You re-run its mechanics on the new merge, then the light '
              'checks, a delta packet review, the pre-check and the dry run.',
              "- You own both packets. Choose the new packet's id (a MET-PERF-04x presumably) and tell me.",
              '',
              "Gate material under D5a: ci/ needs the owner's transport approval of the exact PR head, and a "
              'per-PR merge approval. The review records need the D5a fields; this is a contract change, so '
              'include an oracle outside the candidate.',
              '',
              "Size the new caps from a measured projection rather than a guess. Use 253's 63.log counts (48,918 "
              'starts and ends, about 219 B per record), add headroom for N future packets, and state N. Also '
              'check that every consumer of these limits stays consistent: summarize_nested, '
              "test_build_and_predecessors.py, and the parallel suite's per-worker sinks, if they apply.",
              '',
              'Flow: plan and contract, then review, build, packet review, pre-check and dry run on my word, then '
              "the PR. I prepare the owner's approval command, and the verify runs after it. Light work may start "
              "now. D2's re-sim and delta r4 continue."]},
 {'id': 'Q-DIAGCAP-SIZE',
  'selected': 'A',
  'date': '2026-10-20',
  'decision': '(A) Stay under 32 MiB (Recommended)',
  'relayed': ['Monitor: owner decision Q-DIAGCAP-SIZE (2026-10-20, via the lane monitor), verbatim: "(A) Stay '
              'under 32 MiB (Recommended)". Record it verbatim and dated.',
              "- Size the caps under the verifier's 32 MiB OUTPUT_LIMIT, with no root change: MAX_PROCESS_BYTES 30 "
              'MiB, MAX_EVENTS 140k, MAX_SCAN_LINES 154k, MAX_SCAN_BYTES derived.',
              '- State the headroom (about 9 to 22 packets) and the reserve for all other output (2 MiB).',
              '- Name CHAIN-COMPACTION-001 as the structural follow-up.',
              'Write PLAN r2 with C1-2..C1-7, then contract review r2 (fresh, D5a fields). Light work, go ahead.']}]
LIMITS = {'schemaVersion': 'harness.planeon.ai/diagnostic-caps/v1',
 'packet': 'MET-PERF-041',
 'slot': 253,
 'evidenceClass': 'SOURCE_DELTA_ONLY',
 'acceptedBase': {'commit': '27c54605a3dcdbe86522a6bd18a5e19faa5cb40b',
                  'tree': '334820b5cfc09d41824c2db07f385f765aba70fb',
                  'packets': 252,
                  'newestPacket': 'MET-ENFORCE-038',
                  'newestPacketVerifySeconds': 857},
 'module': 'ci/pytest_diagnostics.py',
 'plan': {'path': 'tools/w03/diagcap/PLAN.md',
          'revision': 3,
          'sha256': '5a2175d8681c8680e03c9f6b0975a8d4e216b6ed231f633d686d4feb113a28b1',
          'buildNotes': {'path': 'tools/w03/diagcap/PLAN_NOTES_R3.md',
                         'sha256': 'f50132a451e50ca2c9d505914ac55ee159e2daa4db01f4c50eb524a781d2d5de',
                         'items': ['C3-1', 'C3-2']}},
 'contractReviews': [{'round': 1,
                      'planRevision': 1,
                      'verdict': 'CHANGES_REQUIRED',
                      'record': 'tools/w03/diagcap/contract-review-round1.json',
                      'recordSha256': '6d2d2811627a812479462f5614275f79f51f728f14d951ac70caab1cbdaf35f3',
                      'findings': ['C1-1',
                                   'C1-2',
                                   'C1-3',
                                   'C1-4',
                                   'C1-5',
                                   'C1-6',
                                   'C1-7',
                                   'C1-8',
                                   'C1-9',
                                   'C1-10',
                                   'C1-11']},
                     {'round': 2,
                      'planRevision': 2,
                      'verdict': 'CHANGES_REQUIRED',
                      'record': 'tools/w03/diagcap/contract-review-round2.json',
                      'recordSha256': '0e17d828318fe81f1561fc3e9bab36303bab7b94bb21e735e370e2bad48050b6',
                      'findings': ['C2-1', 'C2-2', 'C2-3', 'C2-4', 'C2-5']},
                     {'round': 3,
                      'planRevision': 3,
                      'verdict': 'PASS_FOR_BUILD',
                      'record': 'tools/w03/diagcap/contract-review-round3.json',
                      'recordSha256': 'fc7dd376b2aee76cf31176ac841f301ba0335ca2b061a93ed275174ccec92bcd',
                      'findings': ['C3-1', 'C3-2']}],
 'measurement': {'run': "MET-ENFORCE-039's Mac dry run (head 31a7d52e), argv 63, the outer pytest",
                 'result': '16306 passed in 666.74s, then failed closed by the diagnostics stream',
                 'tests': 16306,
                 'sessionSeconds': 666.74,
                 'sessionEnd': {'exitCode': 1,
                                'failed': 0,
                                'incomplete': True,
                                'reasons': ['OUTPUT_LIMIT'],
                                'dropped': 3396},
                 'recordsWritten': 94442,
                 'records': {'START': {'count': 47220, 'meanBytes': 235.3, 'maxBytes': 244},
                             'END': {'count': 47220, 'meanBytes': 208.8, 'maxBytes': 213},
                             'ERROR': {'count': 1, 'bytes': 96},
                             'SESSION_END': {'count': 1, 'bytes': 200}},
                 'diagnosticBytes': 20969573,
                 'producer': 'one Diagnostics per pytest process (conftest.py), sink fd 2; under the parallel '
                             "suite the parent replays every worker's reports into its own single Diagnostics, and "
                             "each worker's own sink carries only its share"},
 'ceiling': {'outputLimitBytes': 33554432,
             'source': "the owner's verifier, verify_pr.py:79 (OUTPUT_LIMIT = 32 * 1024 * 1024), enforced at :558 "
                       '(output ceiling exceeded); not part of this repository',
             'bounds': "the launcher's combined stdout and stderr for the whole run",
             'changed': False,
             'streamCapBytes': 31457280,
             'reserveBytes': 2097152,
             'rule': 'MAX_PROCESS_BYTES + reserveBytes <= outputLimitBytes',
             'otherOutputBytes': {'argv1To62Logs': 55774,
                                  'argv63NonDiagnostic': 25000,
                                  'argv64ZeroBillScan': 956,
                                  'runnerEchoLines': 7988,
                                  'totalAbout': 89718},
             'otherOutputNote': "the launcher's, canary's and runner's few success-path lines were read, not "
                                'measured',
             'reserveOverOtherOutputAbout': 23.4,
             'wholeRunAtWBoundaryAboutBytes': 31545000},
 'recordModel': {'start': 'the 64-hex node digest, a label of at most 70 characters (already at the schema maximum '
                          'in every measured log), the phase, seq and tUs',
                 'end': 'the node, phase, outcome, durationUs, tUs, seq and xfail',
                 'growth': 'sizes grow only by digits: seq gains a sixth digit after 99,999 (the cap allows '
                           '140,000), and tUs and durationUs reach at most 10 digits inside the 1200 s verify cap',
                 'acceptance': 'a non-control record is written only while events_written + 1 + 2 <= event_limit '
                               'and bytes_written + len(record) + 2 * MAX_RECORD_BYTES <= byte_limit; SESSION_END '
                               '(control) is written without the reserve',
                 'digits': "the 900 s worker deadline keeps the parent's tUs below 1e9 us (9 digits), assuming "
                           'collection, the three PARENT_NODES and finish fit in the remaining 100 s; the 6 x 900 '
                           's duration budget over the roughly 68,700 END records of a full run averages under '
                           "100,000 us (5 digits), which bounds the mean, not each record's digit count (C3-1)"},
 'profiles': {'clock': {'firstCallSeconds': 0.0, 'laterCallBaseSeconds': 100.0, 'stepPerCallSeconds': 1e-06},
              'W': {'node': 'tests/test_xxxxxxxxxxxxxxxxxxxxxxxxxxx.py::test_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy[%d]',
                    'phases': ['teardown', 'teardown', 'teardown'],
                    'outcome': 'skipped',
                    'durationSeconds': 0.099999,
                    'xfail': False},
              'R': {'node': 'tests/test_xxxxxxxxxxxxxxxxxxxxxxxxxxx.py::test_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy[%d]',
                    'phases': ['setup', 'call', 'teardown'],
                    'outcome': 'passed',
                    'durationSeconds': 0.012345,
                    'xfail': False},
              'S': {'node': 'x::y[%d]',
                    'phases': ['setup', 'call', 'teardown'],
                    'outcome': 'passed',
                    'durationSeconds': 0.012345,
                    'xfail': False}},
 'profileRules': ["Each profile is driven through the module's own Diagnostics with its default limits (as "
                  'conftest.py constructs it), a counting sink and finish(0), with three START/END pairs per test.',
                  "The clock's first call returns 0.0 (the origin); its n-th call returns 100.0 + n x 1e-6 s, so "
                  'every tUs after the first record has exactly 9 digits.',
                  'W and R node ids give the 70-character label '
                  "test_xxxxxxxxxxxxxxxxxxxxxxxxxxx.py[:32]::test_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy; S's x::y[i] "
                  "gives the label <redacted-node>; %d is the test's index from 0."],
 'caps': [{'name': 'MAX_PROCESS_BYTES',
           'before': 20971520,
           'after': 31457280,
           'beforeSource': '20 * 1024 * 1024',
           'afterSource': '30 * 1024 * 1024'},
          {'name': 'MAX_EVENTS',
           'before': 100000,
           'after': 140000,
           'beforeSource': '100_000',
           'afterSource': '140_000'},
          {'name': 'MAX_SCAN_LINES',
           'before': 110000,
           'after': 154000,
           'beforeSource': '110_000',
           'afterSource': 'MAX_EVENTS + MAX_EVENTS // 10'},
          {'name': 'MAX_SCAN_BYTES',
           'before': 22020096,
           'after': 32505856,
           'beforeSource': 'MAX_PROCESS_BYTES + 1024 * 1024',
           'afterSource': 'MAX_PROCESS_BYTES + 1024 * 1024'}],
 'unchanged': [{'name': 'MAX_RECORD_BYTES', 'value': 1024},
               {'name': 'MAX_NODE_CHARS', 'value': 65536},
               {'name': 'MAX_FAILURES', 'value': 16},
               {'name': 'everythingElse',
                'value': 'the record schema, every fail-closed rule, the 64 argv, .github/workflows/verify.yml, '
                         'conftest.py and the verifier'}],
 'boundaries': [{'id': 'W',
                 'profile': 'W',
                 'module': 'candidate',
                 'lastPass': 22874,
                 'firstFail': 22875,
                 'reason': 'OUTPUT_LIMIT',
                 'lastPassBytes': 31455196,
                 'firstFailBytes': 31455306,
                 'note': 'worst case at constant maximum digits: the maximum among profiles whose records all '
                         'carry the same digit counts (C3-1)'},
                {'id': 'R',
                 'profile': 'R',
                 'module': 'candidate',
                 'lastPass': 23159,
                 'firstFail': 23160,
                 'reason': 'OUTPUT_LIMIT',
                 'lastPassBytes': 31454789,
                 'firstFailBytes': 31455352,
                 'note': 'realistic'},
                {'id': 'S',
                 'profile': 'S',
                 'module': 'candidate',
                 'lastPass': 23333,
                 'firstFail': 23334,
                 'reason': 'EVENT_LIMIT',
                 'lastPassBytes': 27842006,
                 'firstFailBytes': 27842114,
                 'note': 'small records: the event cap binds first'},
                {'id': 'WB',
                 'profile': 'WB',
                 'module': 'candidate',
                 'lastPass': 22836,
                 'firstFail': 22837,
                 'reason': 'OUTPUT_LIMIT',
                 'lastPassBytes': 31455144,
                 'firstFailBytes': 31455498,
                 'note': 'C3-1: W with 9-digit tUs and the digit-sum maximum under the 6 x 900 s duration budget '
                         '(k END records at 100,000 us and the rest at 10,000 us, k = floor((5.4e9 - 3T x 10,000) '
                         '/ 90,000)); the lower bound under that argument'},
                {'id': 'W10',
                 'profile': 'W10',
                 'module': 'candidate',
                 'lastPass': 22775,
                 'firstFail': 22776,
                 'reason': 'OUTPUT_LIMIT',
                 'lastPassBytes': 31455226,
                 'firstFailBytes': 31455336,
                 'note': 'C3-1: W with 10-digit tUs (clock base 1000 s), which only a run past the deadlines could '
                         'produce'},
                {'id': 'W10D',
                 'profile': 'W10D',
                 'module': 'candidate',
                 'lastPass': 22531,
                 'firstFail': 22532,
                 'reason': 'OUTPUT_LIMIT',
                 'lastPassBytes': 31455007,
                 'firstFailBytes': 31455363,
                 'note': 'C3-1: W10 with 10-digit durations (9999.999999 s)'},
                {'id': 'baseW',
                 'profile': 'W',
                 'module': 'base',
                 'lastPass': 15269,
                 'firstFail': 15270,
                 'reason': 'OUTPUT_LIMIT',
                 'lastPassBytes': 20968680,
                 'firstFailBytes': 20969705,
                 'note': 'control: the base module (20 MiB / 100,000 events)'},
                {'id': 'baseR',
                 'profile': 'R',
                 'module': 'base',
                 'lastPass': 15461,
                 'firstFail': 15462,
                 'reason': 'OUTPUT_LIMIT',
                 'lastPassBytes': 20969647,
                 'firstFailBytes': 20969756,
                 'note': 'control: the base module (20 MiB / 100,000 events)'}],
 'boundaryRules': ["Found with the real module (27c5460's bytes with the three constants set), a counting sink and "
                   "the pinned profiles; identical to contract review round 3's independent oracle.",
                   'Whatever the profile, the stream never exceeds byte_limit (31,457,280 B): the largest '
                   'first-failing stream above is 31,455,498 B (WB).',
                   'Before the change, profile R at 16,306 tests (the incident) fails with OUTPUT_LIMIT, first '
                   'failing at test 15,462.'],
 'headroom': {'lastPassingTests': 22874,
              'measuredTests': 16306,
              'testsOverMeasured': 6568,
              'packets': [{'testsPerPacket': 700,
                           'packets': 9,
                           'basis': 'an aggregate rate: 2.4 times the 20-packet mean and 1.85 times the 9-packet '
                                    'mean'},
                          {'testsPerPacket': 378, 'packets': 17, 'basis': 'the recent 9-packet mean'},
                          {'testsPerPacket': 288, 'packets': 22, 'basis': 'the 20-packet mean'}],
              'budgetMixedLowerBound': {'lastPassingTests': 22836, 'testsOverMeasured': 6530},
              'timeLimits': "At 253's load (41 ms per test) the 1200 s verify cap binds near 20,000 tests and the "
                            '900 s worker deadline near 22,000; on a quiet host (25 ms per test) the cap binds '
                            'near 33,000. Diagnostics stop being the first limit under load.'},
 'growth': [{'fromSlot': 233, 'toSlot': 234, 'testsFrom': 10543, 'testsTo': 10722, 'increment': 179, 'packets': 1},
            {'fromSlot': 234, 'toSlot': 238, 'testsFrom': 10722, 'testsTo': 11394, 'increment': 672, 'packets': 4},
            {'fromSlot': 238, 'toSlot': 241, 'testsFrom': 11394, 'testsTo': 12231, 'increment': 837, 'packets': 3},
            {'fromSlot': 241, 'toSlot': 244, 'testsFrom': 12231, 'testsTo': 12905, 'increment': 674, 'packets': 3},
            {'fromSlot': 244, 'toSlot': 246, 'testsFrom': 12905, 'testsTo': 13588, 'increment': 683, 'packets': 2},
            {'fromSlot': 246, 'toSlot': 250, 'testsFrom': 13588, 'testsTo': 14879, 'increment': 1291, 'packets': 4},
            {'fromSlot': 250, 'toSlot': 252, 'testsFrom': 14879, 'testsTo': 15652, 'increment': 773, 'packets': 2},
            {'fromSlot': 252, 'toSlot': 253, 'testsFrom': 15652, 'testsTo': 16306, 'increment': 654, 'packets': 1}],
 'growthNote': 'Only two single-packet increments were measured (179 and 654). 700 per packet is an aggregate '
               'rate; a single packet inside a multi-packet gap may have added more.',
 'consumers': [{'name': 'Diagnostics.__init__',
                'path': 'ci/pytest_diagnostics.py',
                'status': 'follows the constants',
                'detail': 'accepts limits up to MAX_PROCESS_BYTES and MAX_EVENTS'},
               {'name': '_valid_record',
                'path': 'ci/pytest_diagnostics.py',
                'status': 'follows the constants',
                'detail': 'accepts seq up to MAX_EVENTS and SESSION_END counts up to 2 x MAX_EVENTS'},
               {'name': 'summarize_nested',
                'path': 'ci/pytest_diagnostics.py',
                'status': 'follows the constants',
                'detail': 'reads separated nested stderr (capture_output), where each record ends its own line; '
                          'the 10% allowance in the derived MAX_SCAN_LINES covers non-diagnostic stderr lines '
                          '(C1-10); a full-size nested stream at the caps is scanned completely, one byte past '
                          'MAX_SCAN_BYTES gives INPUT_LIMIT and one line past MAX_SCAN_LINES gives SCAN_LIMIT'},
               {'name': 'the predecessor fallback',
                'path': 'tests/linux_runner/test_build_and_predecessors.py',
                'status': 'fits at the new caps',
                'detail': 'used when the in-session proof is unavailable, it runs the whole predecessor suite '
                          "(15,971 tests in 253's proof) in a nested serial pytest, a full-size producer under the "
                          "same caps, which summarize_nested must report COMPLETE; its line-59 comment ('up to "
                          "20MiB of nested structured stderr') becomes stale and stays unchanged on purpose, "
                          'because the file is digest-pinned by earlier layers and a comment-only edit would add a '
                          'pin churn; PREDECESSOR_OUTPUT_LIMIT (65,536) is a separate limit, unchanged'},
               {'name': 'the parallel suite',
                'path': 'ci/parallel_suite.py',
                'status': 'no change',
                'detail': "the parent's single stream carries every worker's replayed reports; each worker's sink "
                          'carries only its share'},
               {'name': "MET-PERF-021's tests",
                'path': 'tests/test_pytest_diagnostics.py',
                'status': 'no edit; the oracle',
                'detail': 'uses the constants symbolically and monkeypatches the scan limits'}],
 'pins': [{'path': 'tests/test_diagnostic_repair.py',
           'line': 133,
           'kind': 'live',
           'pins': 'ci/pytest_diagnostics.py',
           'before': '67416db359a8d5953b469e33b92f0b29f3377fdd6daff7fe1a2958e8bc503a23',
           'after': 'ac9e70395413356f6348180c0c61a7adec57999f770feed59967b6eac7167745',
           'route': "moves to the new file's digest; this packet's reverse hunk spans line 133's bytes only"},
          {'path': 'architecture/packet-schema-performance-authority.json',
           'kind': 'historical (MET-PERF-028 newFiles)',
           'pins': 'ci/pytest_diagnostics.py',
           'value': '67416db359a8d5953b469e33b92f0b29f3377fdd6daff7fe1a2958e8bc503a23',
           'route': 'checked through successor.historical_bytes by scripts/validate_packet_schema_performance.py '
                    "(argv 51); stays byte-identical, reached through this packet's reverse hunk"},
          {'path': 'architecture/packet-schema-performance-authority.json',
           'kind': 'historical (MET-PERF-028 newFiles)',
           'pins': 'tests/test_diagnostic_repair.py',
           'value': '89aaa588c5d130021faa51d90697a09015e34f1038bd85efc1ed9d6d9979f181',
           'route': "reached through this packet's reverse hunk and then MET-PERF-038's"},
          {'path': 'architecture/load-deadlines-authority.json',
           'kind': 'historical (MET-PERF-038 changedFiles)',
           'pins': 'tests/test_diagnostic_repair.py',
           'value': {'before': '89aaa588c5d130021faa51d90697a09015e34f1038bd85efc1ed9d6d9979f181',
                     'after': '7b666bb8bab73ea37037292a53e8f7029f1a9128e0d6379dd75533f2b5e558a2'},
           'route': "reached through this packet's reverse hunk"},
          {'path': 'scripts/validate_load_deadlines.py',
           'kind': 'historical (MET-PERF-038 ERA_SHA256)',
           'pins': 'tests/test_diagnostic_repair.py',
           'value': '7b666bb8bab73ea37037292a53e8f7029f1a9128e0d6379dd75533f2b5e558a2',
           'route': "read through reviewed_bytes, which projects this packet's change away first"},
          {'path': 'tests/test_diagnostic_repair.py',
           'line': 132,
           'kind': 'live, unchanged',
           'pins': 'tests/linux_runner/test_predecessor_diagnostics.py',
           'value': '3c0afe5686f0c39cea2f68d97f50549d0faba890539c3e20aae1d88b2305139f',
           'route': "the mutant at tests/test_load_deadlines.py:859-860 (27c5460's lines; 860-861 at this packet's "
                    'head, where the bridge inserts one line above them, the content unchanged) replaces it '
                    "(3c0afe56 -> 58cabbee) through reviewed_bytes, after the successor projection; this packet's "
                    'hunk touches line 133 only, so line 132 and that mutant are untouched (C3-2)'}],
 'historicalLimitRecords': [{'path': 'task-packets/MET-PERF-028.yaml',
                             'sha256': 'cfa07a1e6d738a0b4ddf531530cba686d0d6c7931e68623c86a63dcdb0e29722',
                             'sentences': ['Fixed added-diagnostic ceilings '
                                           'are20MiB/process,1024bytes/record,100000records',
                                           'Existing32MiB outer ceiling stays unchanged',
                                           'do not echo up to20MiB of metadata through pytest traceback',
                                           'Keep nested420/local750/trusted900/workflow15min,32MiB outer output '
                                           'ceiling, both full replays and all inherited skips',
                                           'Keep all53 commands,420/750/900s,15-minute and32MiB limits'],
                             'status': 'byte-identical; each sentence occurs exactly once, as the record of what '
                                       'MET-PERF-028 decided'},
                            {'path': 'architecture/packet-schema-performance-authority.json',
                             'sha256': 'b22765d800ef757891addcd308570efeefaca1637b806fd28008a800c0cdff4f',
                             'status': "MET-PERF-028's authority, byte-identical"},
                            {'path': 'architecture/load-deadlines-authority.json',
                             'sha256': 'f36e25091fc2c440935d0f8ae5f0687acce9998f30dff5a7cf8327b0a89ce0ab',
                             'status': "MET-PERF-038's authority, byte-identical"},
                            {'path': 'architecture/load-deadlines/limits.json',
                             'sha256': 'f9c152fd4b7e074e5b63b1649e35e2cc2c651060c1ae48d91c078b8690f0f11f',
                             'status': "MET-PERF-038's limits record, byte-identical"},
                            {'path': 'architecture/load-deadlines/README.md',
                             'sha256': '36ee4dd227603e6ebef164a20555c30fabfbd59c0c0dbbd2526579478dcb81c1',
                             'status': "MET-PERF-038's README, byte-identical"},
                            {'path': 'task-packets/',
                             'sha256': None,
                             'status': 'the 51 of the 252 predecessor packet YAMLs that state the 32 MiB outer '
                                       "output ceiling stay byte-identical (pinned by this layer's "
                                       'baselinePackets) and stay true'}],
 'executedChecks': {'W': {'module': 'candidate',
                          'profile': 'W',
                          'reason': 'OUTPUT_LIMIT',
                          'lastPass': {'tests': 22874,
                                       'exitCode': 0,
                                       'incomplete': False,
                                       'reasons': [],
                                       'events': 137245,
                                       'bytes': 31455196,
                                       'dropped': 0,
                                       'firstIncompleteTest': None,
                                       'sinkBytes': 31455196,
                                       'sinkRecords': 137245},
                          'firstFail': {'tests': 22875,
                                        'exitCode': 1,
                                        'incomplete': True,
                                        'reasons': ['OUTPUT_LIMIT'],
                                        'events': 137246,
                                        'bytes': 31455306,
                                        'dropped': 6,
                                        'firstIncompleteTest': 22875,
                                        'sinkBytes': 31455306,
                                        'sinkRecords': 137246}},
                    'S': {'module': 'candidate',
                          'profile': 'S',
                          'reason': 'EVENT_LIMIT',
                          'lastPass': {'tests': 23333,
                                       'exitCode': 0,
                                       'incomplete': False,
                                       'reasons': [],
                                       'events': 139999,
                                       'bytes': 27842006,
                                       'dropped': 0,
                                       'firstIncompleteTest': None,
                                       'sinkBytes': 27842006,
                                       'sinkRecords': 139999},
                          'firstFail': {'tests': 23334,
                                        'exitCode': 1,
                                        'incomplete': True,
                                        'reasons': ['EVENT_LIMIT'],
                                        'events': 140000,
                                        'bytes': 27842114,
                                        'dropped': 6,
                                        'firstIncompleteTest': 23334,
                                        'sinkBytes': 27842114,
                                        'sinkRecords': 140000}},
                    'scan': {'stream': "profile W's stream at its last passing count, padded with non-diagnostic "
                                       'lines (one before it, the rest after its SESSION_END)',
                             'exact': {'status': 'COMPLETE',
                                       'incompleteReasons': [],
                                       'inputBytes': 32505856,
                                       'scannedBytes': 32505856,
                                       'inputTruncatedBytes': 0,
                                       'records': 137245,
                                       'malformed': 0,
                                       'nonDiagnosticLines': 16755,
                                       'completionSeen': True,
                                       'starts': 68622,
                                       'ends': 68622,
                                       'failed': 0,
                                       'skipped': 68622,
                                       'sessionEnd': {'exitCode': 0,
                                                      'incomplete': False,
                                                      'reasons': [],
                                                      'dropped': 0}},
                             'oneBytePast': {'status': 'INCOMPLETE',
                                             'incompleteReasons': ['INPUT_LIMIT'],
                                             'inputBytes': 32505857,
                                             'scannedBytes': 32505793,
                                             'inputTruncatedBytes': 64,
                                             'records': 137245,
                                             'malformed': 0,
                                             'nonDiagnosticLines': 16754,
                                             'completionSeen': True,
                                             'starts': 68622,
                                             'ends': 68622,
                                             'failed': 0,
                                             'skipped': 68622,
                                             'sessionEnd': {'exitCode': 0,
                                                            'incomplete': False,
                                                            'reasons': [],
                                                            'dropped': 0}},
                             'oneLinePast': {'status': 'INCOMPLETE',
                                             'incompleteReasons': ['SCAN_LIMIT'],
                                             'inputBytes': 32505856,
                                             'scannedBytes': 32505856,
                                             'inputTruncatedBytes': 0,
                                             'records': 137245,
                                             'malformed': 0,
                                             'nonDiagnosticLines': 16755,
                                             'completionSeen': True,
                                             'starts': 68622,
                                             'ends': 68622,
                                             'failed': 0,
                                             'skipped': 68622,
                                             'sessionEnd': {'exitCode': 0,
                                                            'incomplete': False,
                                                            'reasons': [],
                                                            'dropped': 0}}},
                    'incident': {'module': 'base',
                                 'profile': 'R',
                                 'outcome': {'tests': 16306,
                                             'exitCode': 1,
                                             'incomplete': True,
                                             'reasons': ['OUTPUT_LIMIT'],
                                             'events': 92768,
                                             'bytes': 20969759,
                                             'dropped': 5070,
                                             'firstIncompleteTest': 15462,
                                             'sinkBytes': 20969759,
                                             'sinkRecords': 92768}}},
 'measuredCost': {'checks': 'the executed checks once each: profile W at 22,874 (collecting the stream) and '
                            '22,875, profile S at 23,333 and 23,334, the three summarize_nested streams and the '
                            "base module's profile R at 16,306",
                  'producerRuns': 5,
                  'summarizeRuns': 3,
                  'wallSeconds': 3.81,
                  'peakRssMiB': 214.4,
                  'processRssBeforeMiB': 26.5,
                  'measuredBy': "the packet builder, in one fresh process, with the layer's own executed-check "
                                "code under the repository venv's interpreter, the one the verify runs (CPython "
                                '3.12.14), at a 1-minute host load average of about 5.8 on 18 CPUs',
                  'budget': 'PLAN.md section 8: about 1-2 s per producer run and at most about 400 MB in all; the '
                            'new test file has no pinned parallel-suite weight (0.05 x its node count), so the '
                            "checks may land on a loaded worker: about 10-25 s more in argv 63 at 253's load"},
 'memory': "summarize_nested holds the caller's captured stderr (a str in the predecessor driver), an encoded "
           'bytes copy and, on INPUT_LIMIT, up to two slices of up to MAX_SCAN_BYTES: about input + input + 2 x 31 '
           'MiB, roughly 200 MB for a full-size stream (review round 1 measured about 411 MB at the 64 MiB caps); '
           "the layer test's full-size checks stay under 400 MB in all",
 'oracle': ["MET-PERF-021's own tests/test_pytest_diagnostics.py passes unchanged (pinned here by digest).",
            "Each contract review ran its own replay oracle in scratch; round 3's (a copy of the module at 27c5460 "
            "and the candidate, sha256 ac9e7039) reproduced every boundary row exactly, and round 1's confirmed "
            'the failure mode under the old caps and the boundary method.'],
 'residuals': [{'id': 'C1-11',
                'status': 'pre-existing, out of scope',
                'text': "The predecessor fallback's serial nested run (about 16,000 tests) cannot finish inside "
                        "its 600 s timeout at today's size, whatever the caps; this packet fixes only the "
                        'diagnostics side of that path.'}],
 'reviewNotes': [{'id': 'C3-1',
                  'text': 'W is the worst case among profiles whose records all carry the same digit counts. Under '
                          'the 6 x 900 s average-duration argument, mixed 5- and 6-digit durations give 22,836 '
                          'tests (WB, 38 below W), and 9-digit tUs also assumes collection plus the parent-run '
                          'tests finish within 100 s; nothing changes in practice: the stream never exceeds '
                          'byte_limit and the headroom stays about 9, 17 and 22 packets.'},
                 {'id': 'C3-2',
                  'text': 'The 3c0afe56 pin in tests/test_diagnostic_repair.py is on line 132, not 131; the '
                          'reverse hunk touches line 133 only, so line 132 and the mutant at '
                          "tests/test_load_deadlines.py:859-860 (27c5460's lines; 860-861 at this packet's head, "
                          'where the bridge inserts one line above them, the content unchanged) are untouched.'}],
 'structuralFollowUp': {'id': 'CHAIN-COMPACTION-001',
                        'decision': 'D9a, after slot 254',
                        'scope': 'the structural follow-up for both the time and the output ceiling'},
 'nextSlot': "MET-ENFORCE-039 (I06-RBAC-V4) moves to slot 254 and re-runs its mechanics on this packet's merge"}


# The pinned boundary profiles (PLAN.md section 3, C2-1). Each is driven through the module's own Diagnostics with its
# default limits (as conftest.py constructs it), a counting sink and finish(0): three START/END pairs per test. The
# clock's first call returns 0.0 (the origin) and its n-th call 100.0 + n x 1e-6 s, so every tUs after the first record
# has 9 digits. W carries the maximum digits on every record (teardown three times, skipped, 0.099999 s, a 70-character
# label); R is realistic (setup, call and teardown, passed, 0.012345 s); S is R with small records (x::y[i], whose label
# is <redacted-node>).
PROFILE_NODE = "tests/test_" + "x" * 27 + ".py::test_" + "y" * 40 + "[%d]"
SMALL_NODE = "x::y[%d]"
PROFILES = MappingProxyType({
    "W": MappingProxyType({"node": PROFILE_NODE, "phases": ("teardown", "teardown", "teardown"), "outcome": "skipped",
                           "durationSeconds": 0.099999, "xfail": False}),
    "R": MappingProxyType({"node": PROFILE_NODE, "phases": ("setup", "call", "teardown"), "outcome": "passed",
                           "durationSeconds": 0.012345, "xfail": False}),
    "S": MappingProxyType({"node": SMALL_NODE, "phases": ("setup", "call", "teardown"), "outcome": "passed",
                           "durationSeconds": 0.012345, "xfail": False}),
})
CLOCK = MappingProxyType({"firstCallSeconds": 0.0, "laterCallBaseSeconds": 100.0, "stepPerCallSeconds": 0.000001})
# The summary fields the scan checks compare (summarize_nested's counters and verdict, never a record's content).
SCAN_FIELDS = ("status", "incompleteReasons", "inputBytes", "scannedBytes", "inputTruncatedBytes", "records", "malformed",
               "nonDiagnosticLines", "completionSeen", "starts", "ends", "failed", "skipped", "sessionEnd")


def diagnostics_module(raw: bytes, name: str) -> types.ModuleType:
    """ci/pytest_diagnostics.py executed from the given bytes (no import, no bytecode)."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / DIAGNOSTICS)
    exec(compile(raw, DIAGNOSTICS, "exec", dont_inherit=True), module.__dict__)
    return module


def run_profile(module: types.ModuleType, name: str, tests: int, collect: bytearray | None = None) -> dict:
    """Drive the module's Diagnostics through `tests` tests of one pinned profile and finish(0); the outcome, with what
    the counting sink saw (and, given a bytearray, a copy of every record written)."""
    profile = PROFILES[name]
    seen = [0, 0]

    def sink(line: bytes) -> int:
        seen[0] += len(line)
        seen[1] += 1
        if collect is not None:
            collect.extend(line)
        return len(line)

    calls = [0]

    def clock() -> float:
        calls[0] += 1
        if calls[0] == 1:
            return CLOCK["firstCallSeconds"]
        return CLOCK["laterCallBaseSeconds"] + calls[0] * CLOCK["stepPerCallSeconds"]

    diagnostics = module.Diagnostics(sink, clock)
    first_incomplete = None
    for index in range(tests):
        node = profile["node"] % index
        for phase in profile["phases"]:
            diagnostics.start(node, phase)
            diagnostics.end(node, phase, profile["outcome"], profile["durationSeconds"], xfail=profile["xfail"])
        if first_incomplete is None and diagnostics.incomplete:
            first_incomplete = index + 1
    exit_code = diagnostics.finish(0)
    return {"tests": tests, "exitCode": exit_code, "incomplete": diagnostics.incomplete,
            "reasons": sorted(diagnostics.reasons), "events": diagnostics.events_written,
            "bytes": diagnostics.bytes_written, "dropped": diagnostics.dropped,
            "firstIncompleteTest": first_incomplete, "sinkBytes": seen[0], "sinkRecords": seen[1]}


def scan_streams(module: types.ModuleType, stream: bytes) -> Any:
    """The three nested-stderr streams of PLAN.md section 8 check 3, built from one complete producer stream: padded with
    non-diagnostic lines (one before it, the rest after its SESSION_END) to exactly the module's MAX_SCAN_BYTES and
    MAX_SCAN_LINES; the same stream with one byte more at its start; and with one line more (its last padding line split
    in two, the byte count unchanged). Yielded one at a time."""
    records = stream.count(b"\n")
    pad_bytes, pad_lines = module.MAX_SCAN_BYTES - len(stream), module.MAX_SCAN_LINES - records
    width, extra = divmod(pad_bytes, pad_lines) if pad_lines > 0 else (0, 0)
    require(pad_lines >= 2 and width >= 3 and stream.endswith(b"\n"),
            "the producer stream leaves room for at least two padding lines of at least three bytes")
    padding = [b"." * (width - 1 + (index < extra)) + b"\n" for index in range(pad_lines)]
    exact = padding[0] + stream + b"".join(padding[1:])
    yield exact
    yield b"." + exact
    yield exact[:-2] + b"\n\n"


def scan_summary(module: types.ModuleType, raw: bytes) -> dict:
    summary = module.summarize_nested(raw)
    return {key: summary[key] for key in SCAN_FIELDS}


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
    require(expected is not None, "MET-PERF-041 reviewed bytes are bound: " + str(path))
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed DIAGNOSTIC-CAPS source: " + path)
    return raw


def _json(path: str) -> Any:
    return parse(_verified(path))


def _holds(check: Any) -> bool:
    """A structural check over this era's data or a module's result; a malformed value does not hold."""
    try:
        return check() is True
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        return False


def _bound(check: Any, message: str) -> None:
    require(_holds(check), message)


def era_inputs() -> types.SimpleNamespace:
    """This era's module and repair test, and 27c5460's bytes of both through this layer's own reverse hunks."""
    raw, repair = _verified(DIAGNOSTICS), _verified(REPAIR_TEST)
    base_raw, base_repair = _undo_this_layer(DIAGNOSTICS, raw), _undo_this_layer(REPAIR_TEST, repair)
    require(digest(base_raw) == BASE_DIAGNOSTICS_SHA256 and digest(base_repair) == BASE_REPAIR_SHA256,
            "this layer's reverse hunks project the module back to 67416db3 and the repair test back to 7b666bb8")
    return types.SimpleNamespace(raw=raw, repair=repair, base_raw=base_raw, base_repair=base_repair)


def validate_contract_files() -> None:
    """The packet adds the contract's two files as new files, each once; the contract directory holds exactly them;
    each is a regular file of git mode 100644, not a link and not executable; and neither holds an absolute local
    path."""
    new = authority()["newFiles"]
    require(len(set(NEW_FILES)) == len(NEW_FILES) and not set(NEW_FILES) & set(_PROJECTION_RULES)
            and {path for path in new if path.startswith(CAPS_DIR)} == set(NEW_FILES),
            "the contract's files are new in this packet, each once")
    require(stat.S_ISDIR(reviewed_mode(CAPS_DIR[:-1])), "the contract directory is a directory, not a link")
    require(set(reviewed_tree(CAPS_DIR)) == CONTRACT_TREE, "the contract directory holds exactly its files")
    for path in NEW_FILES:
        mode = reviewed_mode(path)
        require(stat.S_ISREG(mode) and not mode & 0o111, "a contract file is a regular file of git mode 100644: " + path)
        raw = _verified(path).lower()
        require(not any(marker in raw for marker in LOCAL_PATH_MARKERS),
                "no absolute local path in a file this packet adds: " + path)


def validate_limits_record() -> None:
    """limits.json is closed and equals its restatement here type-strictly (canonical JSON), the owner decisions are
    recorded verbatim and dated, and the restated profiles are the ones the executed checks run."""
    record = _json(LIMITS_RECORD)
    require(type(record) is dict and list(record) == list(LIMITS) + ["ownerDecisions"]
            and canonical({key: record[key] for key in LIMITS}) == canonical(LIMITS),
            "closed diagnostic-caps limits record, equal to its restatement")
    require(canonical(record["ownerDecisions"]) == canonical(OWNER_DECISIONS),
            "owner decisions Q-253-DIAG and Q-DIAGCAP-SIZE recorded verbatim and dated")
    _bound(lambda: list(LIMITS["profiles"]) == ["clock", "W", "R", "S"]
           and canonical(LIMITS["profiles"]) == canonical(dict({name: dict(PROFILES[name]) for name in PROFILES},
                                                               clock=dict(CLOCK))),
           "the restated profiles are the executed profiles")


def validate_caps(raw: bytes, base_raw: bytes) -> types.SimpleNamespace:
    """The module of this era and of 27c5460, executed from their bytes: the three caps and the derived scan limits are
    limits.json's "after" values and the base module's its "before" values, each written as recorded (MAX_SCAN_LINES
    derived in code, MAX_SCAN_BYTES still MAX_PROCESS_BYTES + 1 MiB); the record, node and failure limits are
    unchanged; and nothing else differs, by canonical hunk."""
    new = diagnostics_module(raw, "_met_perf_041_pytest_diagnostics")
    base = diagnostics_module(base_raw, "_met_perf_041_pytest_diagnostics_base")
    caps = LIMITS["caps"]
    _bound(lambda: tuple(row["name"] for row in caps) == CAP_NAMES
           and all(type(getattr(new, row["name"])) is int and getattr(new, row["name"]) == row["after"] for row in caps),
           "the three caps and the derived scan limits are limits.json's after values")
    _bound(lambda: all(type(getattr(base, row["name"])) is int and getattr(base, row["name"]) == row["before"]
                       for row in caps), "the base module's caps are limits.json's before values")
    _bound(lambda: all(raw.count(("\n%s = %s\n" % (row["name"], row["afterSource"])).encode("ascii")) == 1
                       and base_raw.count(("\n%s = %s\n" % (row["name"], row["beforeSource"])).encode("ascii")) == 1
                       for row in caps)
           and new.MAX_SCAN_LINES == new.MAX_EVENTS + new.MAX_EVENTS // 10
           and new.MAX_SCAN_BYTES == new.MAX_PROCESS_BYTES + 1024 * 1024,
           "MAX_SCAN_LINES is derived in code as MAX_EVENTS + MAX_EVENTS // 10 and MAX_SCAN_BYTES as MAX_PROCESS_BYTES "
           "+ 1 MiB")
    _bound(lambda: [row["name"] for row in LIMITS["unchanged"][:3]] == list(KEPT_NAMES)
           and all(getattr(new, row["name"]) == getattr(base, row["name"]) == row["value"]
                   for row in LIMITS["unchanged"][:3]), "the record, node and failure limits are 27c5460's")
    require(canonical_hunks(raw, base_raw) == DIAGNOSTICS_HUNKS,
            "nothing else in ci/pytest_diagnostics.py differs from 27c5460, by canonical hunk")
    return types.SimpleNamespace(new=new, base=base)


def validate_live_pin(repair: bytes, base_repair: bytes, module_sha: str) -> None:
    """tests/test_diagnostic_repair.py's line 133 pins this era's module; line 132 is unchanged; and the reverse hunk
    that gives MET-PERF-038's era bytes back spans line 133's bytes only."""
    lines = repair.split(b"\n")
    _bound(lambda: lines[LIVE_PIN_LINE - 1] == b'        "ci/pytest_diagnostics.py": "%s",' % module_sha.encode("ascii")
           and repair.count(module_sha.encode("ascii")) == 1 and BASE_DIAGNOSTICS_SHA256.encode("ascii") not in repair,
           "tests/test_diagnostic_repair.py's live pin (line 133) is the new module's digest")
    _bound(lambda: lines[UNCHANGED_PIN_LINE - 1] == UNCHANGED_PIN and repair.count(UNCHANGED_PIN) == 1,
           "line 132's pin of the predecessor diagnostics test is unchanged")
    start = sum(len(line) + 1 for line in lines[:LIVE_PIN_LINE - 1])
    end = start + len(lines[LIVE_PIN_LINE - 1])
    hunks = canonical_hunks(repair, base_repair)
    require(hunks == REPAIR_HUNKS and all(start <= at and at + len(removed) <= end for at, removed, _inserted in hunks),
            "the repair test's reverse hunk spans line 133's bytes only")


def validate_ceiling() -> None:
    """The 32 MiB ceiling, the 2 MiB reserve and the stream cap are restated; the stream cap and the reserve fit the
    ceiling; and the reserve covers the measured other output about 23 times over, so the whole run at W's boundary
    stays under the ceiling."""
    ceiling = LIMITS["ceiling"]
    caps = {row["name"]: row["after"] for row in LIMITS["caps"]}
    _bound(lambda: ceiling["outputLimitBytes"] == OUTPUT_CEILING_BYTES and ceiling["reserveBytes"] == RESERVE_BYTES
           and ceiling["streamCapBytes"] == caps["MAX_PROCESS_BYTES"] and ceiling["changed"] is False,
           "the 32 MiB ceiling, the 2 MiB reserve and the stream cap are restated")
    require(caps["MAX_PROCESS_BYTES"] + RESERVE_BYTES <= OUTPUT_CEILING_BYTES,
            "MAX_PROCESS_BYTES and the 2 MiB reserve fit the 32 MiB ceiling")
    other = ceiling["otherOutputBytes"]
    w_bytes = {row["id"]: row for row in LIMITS["boundaries"]}["W"]["lastPassBytes"]
    _bound(lambda: other["totalAbout"] >= sum(value for key, value in other.items() if key != "totalAbout")
           and round(RESERVE_BYTES / other["totalAbout"], 1) == ceiling["reserveOverOtherOutputAbout"]
           and round(w_bytes + other["totalAbout"], -3) == ceiling["wholeRunAtWBoundaryAboutBytes"]
           and w_bytes + other["totalAbout"] < OUTPUT_CEILING_BYTES,
           "the reserve covers the other output, and the whole run at W's boundary stays under the ceiling")


def validate_historical_records() -> None:
    """MET-PERF-028.yaml keeps its five sentences byte-exact; MET-PERF-028's and MET-PERF-038's authorities and
    MET-PERF-038's validator keep their pins of the module and the repair test, which this packet's reverse hunks reach;
    and every historical record, with MET-PERF-021's own tests, is byte-identical at its recorded digest."""
    packet = _verified(PERF_028_PACKET)
    require(all(packet.count(sentence) == 1 for sentence in FIVE_SENTENCES),
            "MET-PERF-028.yaml's five sentences stay byte-exact, once each")
    perf028, perf038 = _json(PERF_028_AUTHORITY), _json(PERF_038_AUTHORITY)
    _bound(lambda: perf028["authorityPacket"] == "MET-PERF-028" and perf028["newFiles"][DIAGNOSTICS] == BASE_DIAGNOSTICS_SHA256
           and perf028["newFiles"][REPAIR_TEST] == PERF_028_REPAIR_SHA256
           and perf028["newFiles"][ORACLE_TEST] == ERA_SHA256[ORACLE_TEST],
           "MET-PERF-028's authority pins the base module, its repair test and its own tests")
    _bound(lambda: perf038["authorityPacket"] == "MET-PERF-038"
           and perf038["changedFiles"][REPAIR_TEST]["beforeSha256"] == PERF_028_REPAIR_SHA256
           and perf038["changedFiles"][REPAIR_TEST]["afterSha256"] == BASE_REPAIR_SHA256,
           "MET-PERF-038's authority pins the repair test before and after its own change")
    pin = b'    "tests/test_diagnostic_repair.py": "%s",\n' % BASE_REPAIR_SHA256.encode("ascii")
    require(_verified(PERF_038_VALIDATOR).count(pin) == 1,
            "MET-PERF-038's validator still pins the repair test at 7b666bb8")
    rules = _PROJECTION_RULES
    _bound(lambda: rules[DIAGNOSTICS]["beforeSha256"] == BASE_DIAGNOSTICS_SHA256
           and rules[DIAGNOSTICS]["afterSha256"] == ERA_SHA256[DIAGNOSTICS]
           and rules[REPAIR_TEST]["beforeSha256"] == BASE_REPAIR_SHA256
           and rules[REPAIR_TEST]["afterSha256"] == ERA_SHA256[REPAIR_TEST],
           "this packet's authority carries the reverse routes to 67416db3 and 7b666bb8")
    recorded = {row["path"]: row["sha256"] for row in LIMITS["historicalLimitRecords"] if row["sha256"] is not None}
    _bound(lambda: recorded == {path: ERA_SHA256[path] for path in HISTORICAL_RECORDS}
           and not (set(recorded) | {ORACLE_TEST}) & (set(rules) | set(authority()["newFiles"])),
           "every historical record is byte-identical at its recorded digest")


def validate_executed_records() -> None:
    """The recorded executed outcomes say what PLAN.md section 8 says and agree with the boundary table, the measurement,
    the caps and the headroom."""
    checks, rows = LIMITS["executedChecks"], {row["id"]: row for row in LIMITS["boundaries"]}
    caps = {row["name"]: row["after"] for row in LIMITS["caps"]}
    for name, reason in (("W", "OUTPUT_LIMIT"), ("S", "EVENT_LIMIT")):
        case, row = checks[name], rows[name]
        last, first = case["lastPass"], case["firstFail"]
        _bound(lambda: case["profile"] == name and case["module"] == row["module"] == "candidate"
               and case["reason"] == row["reason"] == reason and last["tests"] == row["lastPass"]
               and first["tests"] == row["firstFail"] == last["tests"] + 1 and last["bytes"] == row["lastPassBytes"]
               and first["bytes"] == row["firstFailBytes"], "the executed boundary is the boundary table's: " + name)
        _bound(lambda: last == dict(last, exitCode=0, incomplete=False, reasons=[], dropped=0, firstIncompleteTest=None,
                                    events=6 * last["tests"] + 1, sinkRecords=6 * last["tests"] + 1,
                                    sinkBytes=last["bytes"]) and len(last) == 10 and last["bytes"] <= caps["MAX_PROCESS_BYTES"],
               "the last passing count completes with every record written, within the byte cap: " + name)
        _bound(lambda: first == dict(first, exitCode=1, incomplete=True, reasons=[reason], firstIncompleteTest=first["tests"],
                                     sinkRecords=first["events"], sinkBytes=first["bytes"]) and len(first) == 10
               and first["bytes"] <= caps["MAX_PROCESS_BYTES"],
               "one test later fails closed with its reason and exit 1, within the byte cap: " + name)
    incident = checks["incident"]
    _bound(lambda: incident["module"] == "base" and incident["profile"] == "R"
           and incident["outcome"] == dict(incident["outcome"], tests=LIMITS["measurement"]["tests"], exitCode=1,
                                           incomplete=True, reasons=["OUTPUT_LIMIT"],
                                           firstIncompleteTest=rows["baseR"]["firstFail"])
           and rows["baseR"]["module"] == "base" and incident["outcome"]["bytes"] <= LIMITS["caps"][0]["before"],
           "the incident run is the measurement's, failing first where the base R boundary says")
    scan, events = checks["scan"], checks["W"]["lastPass"]["events"]
    _bound(lambda: scan["exact"] == dict(scan["exact"], status="COMPLETE", incompleteReasons=[],
                                         inputBytes=caps["MAX_SCAN_BYTES"], scannedBytes=caps["MAX_SCAN_BYTES"],
                                         inputTruncatedBytes=0, records=events, malformed=0, completionSeen=True,
                                         nonDiagnosticLines=caps["MAX_SCAN_LINES"] - events)
           and scan["oneBytePast"] == dict(scan["oneBytePast"], status="INCOMPLETE", incompleteReasons=["INPUT_LIMIT"],
                                           inputBytes=caps["MAX_SCAN_BYTES"] + 1)
           and scan["oneLinePast"] == dict(scan["oneLinePast"], status="INCOMPLETE", incompleteReasons=["SCAN_LIMIT"],
                                           inputBytes=caps["MAX_SCAN_BYTES"], scannedBytes=caps["MAX_SCAN_BYTES"]),
           "the scan records are COMPLETE at exactly the scan limits, INPUT_LIMIT one byte past and SCAN_LIMIT one line "
           "past")
    headroom = LIMITS["headroom"]
    _bound(lambda: headroom["lastPassingTests"] == rows["W"]["lastPass"]
           and headroom["measuredTests"] == LIMITS["measurement"]["tests"]
           and headroom["testsOverMeasured"] == headroom["lastPassingTests"] - headroom["measuredTests"]
           and all(row["packets"] == headroom["testsOverMeasured"] // row["testsPerPacket"] for row in headroom["packets"])
           and headroom["budgetMixedLowerBound"] == {"lastPassingTests": rows["WB"]["lastPass"],
                                                     "testsOverMeasured": rows["WB"]["lastPass"] - headroom["measuredTests"]},
           "the headroom follows from the boundary table and the measurement")


def executed_checks(m: types.SimpleNamespace) -> None:
    """PLAN.md section 8's executed checks, once each, from this era's bytes at full size, against limits.json's recorded
    outcomes."""
    checks = LIMITS["executedChecks"]
    w, s = checks["W"], checks["S"]
    collected = bytearray()
    require(run_profile(m.new, "W", w["lastPass"]["tests"], collected) == w["lastPass"],
            "profile W completes at its last passing count")
    require(run_profile(m.new, "W", w["firstFail"]["tests"]) == w["firstFail"],
            "profile W fails closed with OUTPUT_LIMIT and exit 1 one test later")
    require(run_profile(m.new, "S", s["lastPass"]["tests"]) == s["lastPass"],
            "profile S completes at its last passing count")
    require(run_profile(m.new, "S", s["firstFail"]["tests"]) == s["firstFail"],
            "profile S fails closed with EVENT_LIMIT one test later")
    stream = bytes(collected)
    collected.clear()
    streams = scan_streams(m.new, stream)
    del stream
    require(scan_summary(m.new, next(streams)) == checks["scan"]["exact"],
            "summarize_nested reports COMPLETE on a stream of exactly MAX_SCAN_BYTES and MAX_SCAN_LINES")
    require(scan_summary(m.new, next(streams)) == checks["scan"]["oneBytePast"],
            "summarize_nested reports INPUT_LIMIT one byte past MAX_SCAN_BYTES")
    require(scan_summary(m.new, next(streams)) == checks["scan"]["oneLinePast"],
            "summarize_nested reports SCAN_LIMIT one line past MAX_SCAN_LINES")
    streams.close()
    require(run_profile(m.base, "R", checks["incident"]["outcome"]["tests"]) == checks["incident"]["outcome"],
            "the base module fails profile R at the incident's 16,306 tests with OUTPUT_LIMIT")


def validate_diagnostic_caps() -> None:
    """Every reviewed byte first; then the contract's files and the limits record; the caps, the live pin, the ceiling,
    the historical records and the recorded executed outcomes; then the executed checks from this era's bytes, once each
    at full size; last, this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_contract_files()
    validate_limits_record()
    era = era_inputs()
    modules = validate_caps(era.raw, era.base_raw)
    validate_live_pin(era.repair, era.base_repair, ERA_SHA256[DIAGNOSTICS])
    validate_ceiling()
    validate_historical_records()
    validate_executed_records()
    executed_checks(modules)
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
            == record["validatorNormalizedSha256"], "diagnostic caps validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 273
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 273-packet catalog retaining the 253-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only diagnostic-caps packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted diagnostic-caps packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_diagnostic_caps()


if __name__ == "__main__":
    validate()
    print("Diagnostic caps valid: 273 current specifications; 253-packet checkpoint and exact 252-packet predecessor; contract reviewed.")
