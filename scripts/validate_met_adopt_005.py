#!/usr/bin/env python3
"""Validate the MET-ADOPT-005 H10 execution authority (TECH-ORCHESTRATION-001): ADR 0011, the new H10 planning-target block, the R08 clause and the status line (V1-V6: the H10 block and the base's other lines, the R08 line with lines 101-102 and the rest as at the base, ADR 0011's bytes and its superseded-texts table with each fragment once, the superseded texts and the provider catalog as at the base, the one status line and the registry's MET-ADOPT-005/packet rider), and the exact 268-to-267 projection."""
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
    import validate_met_gov_005 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_met_gov_005 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/met-adopt-005-authority.json"
AUTHORITY_SHA256 = "a4dce2d89acdd12145074624dc891914a2c5db26174b4c67875fcdece38e8a58"
VALIDATOR_PATH = "scripts/validate_met_adopt_005.py"
BASE_COMMIT = "ee26624dd91dbccb7516914ca0df83874d2c6a9f"
NEW_PACKET = "MET-ADOPT-005"
PREVIOUS_PACKET = "MET-GOV-004"
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
            require(key not in result, "duplicate h10-execution-authority authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite h10-execution-authority authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "h10 execution authority history authority digest")
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
    }, "closed h10 execution authority history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/met-adopt-005-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 267
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 267-packet base")
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
    # An exact 267-era byte string is already older than the successor layer.
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


# MET-ADOPT-005 (roadmap TECH-ORCHESTRATION-001; the owner's TECH-D1 and Q-TO-6, and the lane monitor's owner-delegated
# rulings MON-TECHORCH-1, MON-TECHORCH-2 and MON-TECHORCH-M1) records the H10 execution authority. ADR 0011,
# docs/adr/0011-h10-execution-authority.md, makes the PostgreSQL executor H10's qualified baseline and Temporal an
# optional provider, and names the superseded older planning texts by path and line without editing them. The H10
# harness document docs/harnesses/execution.orchestration.md takes the new planning-target block on its lines 16-20, the
# R08 plan docs/repositories/08-mas-harness-execution-plane.md takes one clause on its line 103 (lines 101-102, which
# ADR 0010's spans cite, are unchanged), and docs/DEVELOPMENT_STATUS.md gains one line citing the ADR. The packet's
# review series is registered by its own rider in architecture/review-record/briefs.json (the MET-ADOPT-005/packet
# entry); the rider and the H10 harness document are gate material in the evolution surface record at this base, so the
# owner approves the PR. Repository bytes are read only through reviewed_bytes, so a later bridged successor projects
# its own edits away first; a path outside this era is refused before it is read, every era file is bound by digest on
# every read, and no directory is listed. Each refusal is a pure check over the values read, so every one has a failing
# case on plain data. Every constant of the checks is computed at the base or taken from the design. Checked here: V1,
# the H10 document (lines 16-20 are exactly the new block, its other lines are the base's, and this layer's inverse
# restores the withdrawn base block); V2, the R08 plan (line 103 is exactly the new clause, and lines 101-102 and its
# other lines are the base's); V3, ADR 0011 (its bytes equal the pinned digest, its superseded-texts table is exactly
# SUPERSEDED, each fragment occurs exactly once in its file, and the superseded texts other than the master plan are the
# base's); V4, the provider catalog is the base's (Q-TO-4); V5, the status file is the base's with the one ADR 0011 line
# inserted directly after the ADR 0010 line; and V6, the registry differs from the base by exactly this packet's rider.
# No chain validator or chain test is pinned here. Last, this layer's own inverse hunks are the canonical byte-minimal
# ones, recomputed from its era's bytes (MET-PERF-040's carried rule).
H10_PATH = "docs/harnesses/execution.orchestration.md"
R08_PATH = "docs/repositories/08-mas-harness-execution-plane.md"
ADR_PATH = "docs/adr/0011-h10-execution-authority.md"
STATUS_PATH = "docs/DEVELOPMENT_STATUS.md"
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
CATALOG_PATH = "architecture/providers.yaml"
MASTER_PATH = "docs/MASTER_DEVELOPMENT_PLAN.md"
# V1: the new block B1-B5 (design section 3) on lines 16-20; the base's other lines and its withdrawn block.
H10_FIRST = 16
H10_LAST = 20
H10_BLOCK = (
    ("Planning target: `planeon.orchestrator.postgres` (PostgreSQL leases and outbox) as H10's qualified "
     "baseline; `temporalio/temporal` is an optional provider ([ADR "
     "0011](../adr/0011-h10-execution-authority.md))."),
    ("For the first enterprise release PostgreSQL owns leases, task transitions, checkpoints, timers, retries "
     "and outbox coordination, on the tenant-supplied PostgreSQL every profile already requires. Temporal is "
     "an optional provider module that `EXEC-TEMPORAL-001` qualifies behind the same public task contracts; it "
     "is never a second retry or side-effect authority for a task, and it is selectable only with a catalog "
     "record, a repository packet and conformance evidence. LangGraph is a later agent-logic adapter, not a "
     "second retry/side-effect authority for the same task."),
    ("Platform scope: Own task API, business intent, policy admission, approvals, receipts and tool broker "
     "integration. Complete the PostgreSQL executor to the parity, fencing and resume vectors, with no "
     "general-purpose engine beyond H10's contracts."),
    ("Delivery: `EXEC-ORCH-001` (the PostgreSQL baseline) and `EXEC-TEMPORAL-001` (the optional Temporal "
     "provider; ALPHA_2, WAITING_PACKET_PUBLICATION)."),
    ("Acceptance: the baseline is held to the durable-execution parity vectors, the fencing tokens and "
     "operation IDs, and the resume vectors. For `EXEC-TEMPORAL-001`, behind the same public task contracts "
     "and with its measured comparison: Prove signals/approval waits, restart/replay, cancellation, idempotent "
     "activities, duplicate-side-effect prevention and retention under local Linux. Worker nondeterminism, "
     "workflow version upgrades and PostgreSQL history export/drain require reviewed rollback. Temporal does "
     "not guarantee exactly-once external effects."),
)
H10_REST_SHA256 = "634a22077ba3207c65b1acdd2336ac76ec9f7ad2346ed546877628a3751b66b1"
H10_WITHDRAWN_SHA256 = "5d66bdf71ace711f18dcbb2ff89cdd25bc45a259aa4ac2e4cb09e083e49e6a32"
# V2: the new clause (design section 4) on line 103; lines 101-102 and the other lines as at the base.
R08_LINE_NUMBER = 103
R08_LINE = ("- Baseline durable executor uses PostgreSQL leases/outbox. Temporal is a separate optional "
            "provider module; it cannot change public task semantics, and it is selectable only with a catalog "
            "record, a repository packet and conformance evidence.")
R08_SPAN_SHA256 = "cb0d55a0ecb58f2cbebcc3fb3fc65a2633f431e4c81459a5d026d3bb1906deb9"
R08_REST_SHA256 = "bf15db718cdfcba7463a2c79e4328a469c5daa46686672dd0c9304e8830f3c96"
# V3: ADR 0011 (design section 5), its superseded-texts table (path, lines at the base, fragment), the files it names,
# and the base digests of those other than the master plan (Q-TO-1: superseded by reference only).
ADR_SHA256 = "60a8250ecce83e9ee3655726b90db22e526eb69aac163d9e2eb60977a81c5685"
SUPERSEDED_HEADING = "## Superseded planning texts (for H10 only)"
SUPERSEDED = (
    ("docs/adr/0008-reuse-first-harness-implementation.md",
     "14",
     "Temporal self-hosted"),
    ("docs/adr/0008-reuse-first-harness-implementation.md",
     "27-28",
     "keep its bespoke-executor expansion"),
    ("docs/MASTER_DEVELOPMENT_PLAN.md",
     "2578",
     "a separately decided Temporal transition"),
    ("docs/MASTER_DEVELOPMENT_PLAN.md",
     "2580",
     ("The existing PostgreSQL durable-execution source stays historical while R08 decides the Temporal "
      "successor, migration, history replay and single side-effect authority.")),
    ("docs/alpha-2/PROVIDER_ADOPTION_ROADMAP.md",
     "400-401",
     "Further bespoke durable-executor"),
    ("docs/alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md",
     "43",
     "[temporalio/temporal](https://github.com/temporalio/temporal)"),
    ("docs/alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md",
     "163-169",
     "Plan self-hosted Temporal as the preferred durable execution engine."),
    ("docs/alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md",
     "302",
     ("Temporal is a planned target, not an authorized runtime change. EXEC-ORCH-001 must not be dispatched "
      "for further bespoke executor growth.")),
    ("docs/alpha-2/UNIFIED_ROADMAP_TRACEABILITY.md",
     "87",
     "Temporal adoption decision"),
    ("docs/alpha-2/UNIFIED_ROADMAP_TRACEABILITY.md",
     "119",
     "research adoption prefers Temporal"),
)
SUPERSEDED_FILES = ("docs/adr/0008-reuse-first-harness-implementation.md",
                    "docs/MASTER_DEVELOPMENT_PLAN.md",
                    "docs/alpha-2/PROVIDER_ADOPTION_ROADMAP.md",
                    "docs/alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md",
                    "docs/alpha-2/UNIFIED_ROADMAP_TRACEABILITY.md")
UNCHANGED_SHA256 = MappingProxyType({
    "docs/adr/0008-reuse-first-harness-implementation.md": "395b2c3e1ecffcef060ef23b68975eb5550555f519bbfc4b3b07cba4f3fdc8ac",
    "docs/alpha-2/PROVIDER_ADOPTION_ROADMAP.md": "e25a8a7e996cf48b8f5df006acabe23eded4357045568a3332bdc4dde4df8293",
    "docs/alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md": "f6a891e8bdbcc579e60800773addd70ca29a2c4021c2dc95af62be93e91f061d",
    "docs/alpha-2/UNIFIED_ROADMAP_TRACEABILITY.md": "973bcc48e846691401eecc2280ad6b4c1f78c09c278308ab52f082d4231ba96f",
})
# V4: the provider catalog's base digest (Q-TO-4).
CATALOG_SHA256 = "9e2b43dac1ca4531dcdeb3a1b6ead8002d7384e2a0d0e6b57e972accb8631c02"
# V5: the status line (design section 6), directly after the base's ADR 0010 line, on the base's bytes.
STATUS_LINE = ("[H10 execution authority ADR 0011](adr/0011-h10-execution-authority.md) (MET-ADOPT-005) "
               "records the owner's TECH-D1: PostgreSQL leases and outbox own H10 execution; Temporal is an "
               "optional provider.")
STATUS_ANCHOR = ("[Language placement ADR 0010](adr/0010-language-placement.md) (MET-GOV-004) records the "
                 "planned-language baseline at 9184f5b6; its exceptions are pending LANG-HOTPATH-DECISION-001.")
STATUS_BASE_SHA256 = "3cd2630bc525a81098a92f9c43c5695de5803df76002415174d54e61bff14684"
# V6: the registry at the base (the digest of its canonical JSON) and this packet's one rider, pinning the generic
# packet brief.
REGISTRY_BASE_SHA256 = "af31490b8d2a2ddc72d7bbd026cb6d4a718395d66250dc3172f8e3c235666357"
RIDER = ("PACKET", NEW_PACKET + "/packet", PACKET_BRIEF, "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274", 1)
# Every file this era's check reads, with its digest.
ERA_SHA256 = MappingProxyType({
    "architecture/providers.yaml": "9e2b43dac1ca4531dcdeb3a1b6ead8002d7384e2a0d0e6b57e972accb8631c02",
    "architecture/review-record/briefs.json": "eae9430e6e81d45a7e49586d6d238000c3dd34e7f79d54dfc96f097dd78311d4",
    "docs/DEVELOPMENT_STATUS.md": "7369316ee63521f6872453b4362abb9b1015f344e98b0a71b30cd3998605045b",
    "docs/MASTER_DEVELOPMENT_PLAN.md": "b8f2c3f49312a7a77dc82030ee60bf0e869e9a178eb6002001cabd7395afd5dd",
    "docs/adr/0008-reuse-first-harness-implementation.md": "395b2c3e1ecffcef060ef23b68975eb5550555f519bbfc4b3b07cba4f3fdc8ac",
    "docs/adr/0011-h10-execution-authority.md": "60a8250ecce83e9ee3655726b90db22e526eb69aac163d9e2eb60977a81c5685",
    "docs/alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md": "f6a891e8bdbcc579e60800773addd70ca29a2c4021c2dc95af62be93e91f061d",
    "docs/alpha-2/PROVIDER_ADOPTION_ROADMAP.md": "e25a8a7e996cf48b8f5df006acabe23eded4357045568a3332bdc4dde4df8293",
    "docs/alpha-2/UNIFIED_ROADMAP_TRACEABILITY.md": "973bcc48e846691401eecc2280ad6b4c1f78c09c278308ab52f082d4231ba96f",
    "docs/harnesses/execution.orchestration.md": "32b80f130bd4a5d9babf0731ace2b239034c8d07afcfba6742f1ada4335a31f2",
    "docs/repositories/08-mas-harness-execution-plane.md": "4f0742b6ab9aa1f2e1fa0b80edf8ff855e14e34a7f6ca83503aca1e999dbe397",
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-ADOPT-005 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed TECH-ORCHESTRATION source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-ADOPT-005 reviewed bytes are bound: " + str(path))
    return _era_bytes(path, reviewed_bytes(path))


def _parsed(raw: Any) -> Any:
    """raw as this layer's strict JSON, or None when it is not bytes holding such JSON."""
    try:
        return parse(raw) if type(raw) is bytes else None
    except ValueError:
        return None


def _lines(raw: Any) -> Any:
    """raw's UTF-8 text as its lines, each without its newline, or None unless raw is newline-terminated UTF-8."""
    if type(raw) is not bytes or not raw.endswith(b"\n"):
        return None
    try:
        return raw.decode("utf-8").split("\n")[:-1]
    except ValueError:
        return None


def _lines_sha(lines: Any) -> str:
    """The sha256 of lines, in order, each with its newline."""
    return digest("".join(line + "\n" for line in lines).encode("utf-8"))


def _holds(check: Any) -> bool:
    """A structural check over this era's data; a malformed value does not hold."""
    try:
        return check() is True
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        return False


def _bound(check: Any, message: str) -> None:
    require(_holds(check), message)


def check_h10(raw: Any, before: Any) -> None:
    """V1: lines 16-20 are exactly B1-B5, the other lines are the base's, and this layer's inverse (before) restores the
    withdrawn base block with the same other lines."""
    lines, previous = _lines(raw), _lines(before)
    _bound(lambda: tuple(lines[H10_FIRST - 1:H10_LAST]) == H10_BLOCK,
           "the H10 document's lines 16-20 are exactly the new block B1-B5")
    _bound(lambda: _lines_sha(lines[:H10_FIRST - 1] + lines[H10_LAST:]) == H10_REST_SHA256,
           "the H10 document's other lines are the base's")
    _bound(lambda: _lines_sha(previous[H10_FIRST - 1:H10_LAST]) == H10_WITHDRAWN_SHA256
           and _lines_sha(previous[:H10_FIRST - 1] + previous[H10_LAST:]) == H10_REST_SHA256,
           "this layer's inverse restores the withdrawn H10 block")


def check_r08(raw: Any) -> None:
    """V2: line 103 is exactly the new clause; lines 101-102 (ADR 0010's spans) and the other lines are the base's."""
    lines = _lines(raw)
    _bound(lambda: lines[R08_LINE_NUMBER - 1] == R08_LINE, "the R08 plan's line 103 is exactly the new clause")
    _bound(lambda: _lines_sha(lines[R08_LINE_NUMBER - 3:R08_LINE_NUMBER - 1]) == R08_SPAN_SHA256,
           "the R08 plan's lines 101-102 are the base's")
    _bound(lambda: _lines_sha(lines[:R08_LINE_NUMBER - 3] + lines[R08_LINE_NUMBER:]) == R08_REST_SHA256,
           "the R08 plan's other lines are the base's")


def _superseded_rows(raw: Any) -> Any:
    """ADR 0011's superseded-texts table as (path, lines, fragment) rows in order, or None when it is malformed."""
    parts = raw.decode("utf-8").split("\n" + SUPERSEDED_HEADING + "\n")
    if len(parts) != 2:
        return None
    rows = []
    for line in parts[1].split("\n## ")[0].split("\n"):
        if not line.startswith("| `"):
            continue
        cells = line.split(" | ")
        if (len(cells) != 4 or not cells[0].endswith("`") or not cells[2].startswith('"')
                or not cells[2].endswith('"') or not cells[3].endswith(" |")):
            return None
        rows.append((cells[0][3:-1], cells[1], cells[2][1:-1]))
    return tuple(rows)


def check_adr(raw: Any) -> None:
    """V3: ADR 0011's bytes equal its pinned digest."""
    _bound(lambda: type(raw) is bytes and digest(raw) == ADR_SHA256, "ADR 0011's bytes equal its pinned digest")


def check_superseded_table(raw: Any) -> None:
    """V3: ADR 0011's superseded-texts table is exactly SUPERSEDED (path, lines at the base, fragment, in order)."""
    _bound(lambda: _superseded_rows(raw) == SUPERSEDED, "ADR 0011's superseded-texts table is exactly SUPERSEDED")


def check_superseded_files(files: Any) -> None:
    """V3: the superseded texts are exactly the table's files; each fragment occurs exactly once in its file, located by
    content; and every file other than the master plan is the base's."""
    _bound(lambda: type(files) is dict and sorted(files) == sorted(SUPERSEDED_FILES)
           and len(files) == len(SUPERSEDED_FILES), "the superseded texts are exactly ADR 0011's files")
    for path, _lines_at_base, fragment in SUPERSEDED:
        _bound(lambda: files[path].decode("utf-8").count(fragment) == 1,
               "a superseded fragment occurs exactly once in its file: " + path)
    for path, expected in UNCHANGED_SHA256.items():
        _bound(lambda: type(files[path]) is bytes and digest(files[path]) == expected,
               "a superseded planning text is the base's: " + path)


def check_catalog(raw: Any) -> None:
    """V4 (Q-TO-4): the provider catalog's bytes are the base's."""
    _bound(lambda: type(raw) is bytes and digest(raw) == CATALOG_SHA256, "the provider catalog is the base's (Q-TO-4)")


def check_status(raw: Any) -> None:
    """V5 (BR-TO-2): the status file is the base's lines with the ADR 0011 line inserted directly after the ADR 0010
    line, and nothing else."""
    lines = _lines(raw)
    _bound(lambda: lines.count(STATUS_LINE) == 1 and lines.index(STATUS_LINE) > 0
           and lines[lines.index(STATUS_LINE) - 1] == STATUS_ANCHOR
           and _lines_sha(lines[:lines.index(STATUS_LINE)] + lines[lines.index(STATUS_LINE) + 1:]) == STATUS_BASE_SHA256,
           "the status file is the base's with the ADR 0011 line after the ADR 0010 line")


def check_registry(raw: Any) -> None:
    """V6 (BR-TO-2): the registry differs from the base by exactly one entry, this packet's MET-ADOPT-005/packet rider
    pinning the generic packet brief; nothing else in it changes."""
    registry = _parsed(raw)
    _bound(lambda: type(registry) is dict and type(registry["briefs"]) is list
           and [entry for entry in registry["briefs"] if entry["series"].startswith(NEW_PACKET + "/")]
           == [{"kind": RIDER[0], "series": RIDER[1], "path": RIDER[2], "sha256": RIDER[3], "version": RIDER[4]}]
           and digest(canonical(dict(registry, briefs=[entry for entry in registry["briefs"]
                                                      if not entry["series"].startswith(NEW_PACKET + "/")])))
           == REGISTRY_BASE_SHA256,
           "the registry differs from the base by exactly the MET-ADOPT-005/packet rider")


def validate_h10() -> None:
    """V1 over this era's H10 document and this layer's inverse of it."""
    raw = _verified(H10_PATH)
    check_h10(raw, _undo_this_layer(H10_PATH, raw))


def validate_met_adopt_005() -> None:
    """Every reviewed byte first; then V1 to V6; last, this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_h10()
    check_r08(_verified(R08_PATH))
    adr_raw = _verified(ADR_PATH)
    check_adr(adr_raw)
    check_superseded_table(adr_raw)
    check_superseded_files({path: _verified(path) for path in SUPERSEDED_FILES})
    check_catalog(_verified(CATALOG_PATH))
    check_status(_verified(STATUS_PATH))
    check_registry(_verified(REGISTRY_PATH))
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
            == record["validatorNormalizedSha256"], "h10 execution authority validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 273
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 273-packet catalog retaining the 268-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only h10-execution-authority packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted h10-execution-authority packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_met_adopt_005()


if __name__ == "__main__":
    validate()
    print("H10 execution authority valid: 273 current specifications; 268-packet checkpoint and exact 267-packet predecessor; contract reviewed.")
