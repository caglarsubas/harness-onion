#!/usr/bin/env python3
"""Validate the MET-MAS-003 run-event contract and the exact 233-to-232 projection."""
from __future__ import annotations

import ast
import base64
import binascii
import copy
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
    import validate_load_deadlines as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_load_deadlines as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/run-events-authority.json"
AUTHORITY_SHA256 = "3539777d314053cb670337368cde76e344b276c1505895947695a5a681ba978d"
VALIDATOR_PATH = "scripts/validate_run_events.py"
BASE_COMMIT = "5da126570973293e1075459efe7cf99038f378c9"
NEW_PACKET = "MET-MAS-003"
PREVIOUS_PACKET = "MET-ENFORCE-025"
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
            require(key not in result, "duplicate run-events authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite run-events authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "run events history authority digest")
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
    }, "closed run events history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/run-events-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 232
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 232-packet base")
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
    # An exact 232-era byte string is already older than the successor layer.
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


# MET-MAS-003 (roadmap MAS-RA-003) publishes the run-event, OpenTelemetry GenAI mapping and MAS metrics contract candidate
# (architecture/run-events/): three closed schemas (the run-event log with its operations, phases and attributes; the MAS
# metrics report with eighteen exact rationals; the MAST annotation over the paper's fourteen modes), a standard-library
# reference model and vectors, adopted after three independent review rounds, with H15's, H16's and H10's harness
# documents and the repository schemas byte-identical. Repository bytes are read only through reviewed_bytes, so a later
# bridged successor projects its own edits away first. Every reviewed file of this era is bound by digest before anything
# is parsed, every later read is checked against that digest again, and the contract's model is executed from this era's
# reviewed bytes, with the agent-loop model of this era's bytes as its `loop` argument, to replay every vector and OTel
# projection, so a later revision of either model cannot change how this layer judges its era. The owner's decisions, the
# codes, the schema identities, the metric list, the MAST and OTel sources and the vector counts are restated here
# independently of the reviewed files.
CONTRACT_DIR = "architecture/run-events/"
MODEL = "scripts/run_events.py"
LOOP_MODEL = "scripts/agent_loop.py"
README_PATH = CONTRACT_DIR + "README.md"
SCHEMA_FILES = ("run-event-log.schema.json", "mas-metrics.schema.json", "mast-annotation.schema.json")
SCHEMA_IDS = {"run-event-log.schema.json": "planeon.internal.run-event-log/v1",
              "mas-metrics.schema.json": "planeon.internal.mas-metrics/v1",
              "mast-annotation.schema.json": "planeon.internal.mast-annotation/v1"}
VECTORS_PATH = CONTRACT_DIR + "vectors.json"
VECTORS_SCHEMA = "planeon.internal.run-events-vectors/v1"
STATUS_PATH = CONTRACT_DIR + "status.json"
H10_PATH = "docs/harnesses/execution.orchestration.md"
H15_PATH = "docs/harnesses/trust.observability-finops.md"
H16_PATH = "docs/harnesses/trust.evaluation-assurance.md"
REVIEWED_SUBJECT = {"commit": "9495150ce6677e44ce6c6df0b7c03eb7dcc471d5", "tree": "aa9ef02576c6d3884db9c87f8c332d70dc83209c"}
ROUNDS = ((1, 'CHANGES_REQUIRED'), (2, 'CHANGES_REQUIRED'), (3, 'PASS_FOR_SOURCE_PUBLICATION'))
LAST_ROUND = len(ROUNDS)
REVIEW_SCHEMA = "harness.planeon.ai/run-events-review/v1"
STATUS_KEYS = ("schemaVersion", "workItem", "status", "contract", "reviewedSubject", "adoptionEdit", "rounds", "carried",
               "acceptance", "ownerDecisions", "nonClaims")
ROW_KEYS = ("round", "subject", "subjectTree", "verdict", "record", "snapshot", "severities")
# An earlier round's snapshot holds these files; its vectors.json (regenerated every round) is bound by digest. The last
# round's subject is the adopted contract itself.
SNAPSHOT_FILES = ("README.md",) + SCHEMA_FILES + ("scripts/run_events.py",)
CONTRACT = {"schemas": [CONTRACT_DIR + name for name in SCHEMA_FILES], "vectors": VECTORS_PATH, "model": MODEL,
            "readme": README_PATH}
STATUS_LINE = ("Status: **CONTRACT_CANDIDATE** (independent review round 3).",
               "Status: **ADOPTED_CONTRACT_CANDIDATE** (independent review round 3: PASS_FOR_SOURCE_PUBLICATION; rounds and review records in `status.json`).")
SEVERITIES = ("MAJOR", "MINOR", "NOTE")
NON_CLAIMS = ["An internal contract candidate: no public contract, selector, catalog, schema or runtime change; H15's, H16's and H10's harness documents and the repository schemas are byte-identical.",
              "No collector, exporter, store or dashboard exists (H15's TRUST-OBS-001 and SDK-002); no telemetry leaves the tenant; the model runs only on the vectors.",
              "The OpenTelemetry GenAI conventions are pinned at a development-stability commit, re-pinned at their first release; the MAST vocabulary is the paper's, cited by page, its definitions not restated."]
CARRIED_TO = "the first consumer (MAS-RA-004 or R09) or a later run-events revision"
ACCEPTANCE = ["MAS-RA-003-A1", "MAS-RA-003-A2", "MAS-RA-003-A3"]
DECISIONS = ["Q-233 (a)", "Q-MAS3-A (a)", "Q-MAS3-B (a)", "Q-MAS3-C (a)", "Q-MAS3-D (D-a)", "Q-MAS3-E (a)",
             "Q-MAS3-F (a), as corrected"]
LOG_CODES = ('SHAPE', 'DUPLICATE_ID', 'SEQUENCE', 'RUN_BOUNDS', 'SPAN_ORDER', 'RUN_SCOPE', 'LOGICAL_TIME', 'TIME_ORDER', 'MESSAGE_PAIRING', 'CLAIM_CONFLICT', 'UNKNOWN_REFERENCE', 'SOURCE_BINDING', 'DERIVATION')
METRIC_CODES = ('SHAPE', 'UNKNOWN_REFERENCE', 'METRIC_INPUT', 'METRIC_VALUE')
ANNOTATION_CODES = ('SHAPE', 'DUPLICATE_ID', 'UNKNOWN_REFERENCE', 'ANNOTATION_INPUT', 'ANNOTATION_EVIDENCE')
# Q-MAS3-E (a): eighteen metrics, each an exact rational with a declared unit, in report order.
METRICS = (('cost_per_success', 'cost-micros/success'), ('speedup', 'ratio'), ('parallel_efficiency', 'ratio'), ('message_overhead', 'messages/work-span'), ('token_overhead', 'ratio'), ('duplicated_work_ratio', 'ratio'), ('conflicting_claim_rate', 'ratio'), ('merge_conflict_rate', 'ratio'), ('idle_time', 'ms'), ('orchestrator_bottleneck_time', 'ms'), ('invalid_actions', 'count'), ('retries', 'count'), ('replans', 'count'), ('stalled_turns', 'count'), ('evidence_coverage', 'ratio'), ('unresolved_fraction', 'ratio'), ('verifier_disagreement', 'ratio'), ('denied_capability_attempts', 'count'))
# Q-MAS3-F (a), as corrected: the MAST paper's copy the owner placed, by digest; its three categories and fourteen modes.
MAST_SHA256 = "1b9e317a2a421e60ca2b2eda4a30844557a01e63286a790890c0ecef32d25460"
MAST_MODES = (('FM-1.1', 'FC1'), ('FM-1.2', 'FC1'), ('FM-1.3', 'FC1'), ('FM-1.4', 'FC1'), ('FM-1.5', 'FC1'), ('FM-2.1', 'FC2'), ('FM-2.2', 'FC2'), ('FM-2.3', 'FC2'), ('FM-2.4', 'FC2'), ('FM-2.5', 'FC2'), ('FM-2.6', 'FC2'), ('FM-3.1', 'FC3'), ('FM-3.2', 'FC3'), ('FM-3.3', 'FC3'))
# Q-MAS3-D (D-a): semantic-conventions-genai at one commit, its seven files by digest.
OTEL_COMMIT = "4e8a2812139b2a999d959e3650e24dfc64e21943"
OTEL_FILES = {
    "model/gen-ai/entities.yaml": "f2bc7e63f692e5ddaf2594ca0cad25d835c6dad40157a003a4c80df2c4b2a8d0",
    "model/gen-ai/events.yaml": "09095a702c18da3c883a5d2f053135c9ea253beac1f73079a253fe36e62f08d2",
    "model/gen-ai/metrics.yaml": "2d96085fa29546af30de36c48579ef703365f1eb7cbc43b6a6d2d20dcef01cf6",
    "model/gen-ai/registry.yaml": "fc7326952a9666e791a0af0ea3e07c9bdde4c46a526d36c2057685518ef37f1e",
    "model/gen-ai/spans.yaml": "1f60d7d2685f07de8f4bb0c1834a0cf4124c2f1779ca8e855ceb131b0b48e657",
    "model/gen-ai/token-metrics.yaml": "66431869685e0f7b75d50f68fdfc228dfc0ad2a16c1188928fa69e619b4e4a19",
    "model/manifest.yaml": "53f3589761cd853c6d234761cd07290ee6bc58b4b9758bc4b7b7039c3343e7b6"
}
VECTOR_COUNTS = {"cases": 52, "valid": 14, "texts": 3, "otelProjections": 2, "logs": 13, "traces": 40, "manifests": 2}
# Every harness document (H15's, H16's and H10's among them), the agent-loop contract and its model, and every repository
# schema stay byte-identical (Q-MAS3-A), changed or added.
FROZEN_PATHS = (H10_PATH, H15_PATH, H16_PATH, LOOP_MODEL)
FROZEN_PREFIXES = ("schemas/", "docs/harnesses/", "architecture/agent-loop/")
# The adopted bytes of every contract file, round copy and review record, the status record and the model; the accepted
# base's agent-loop model and its H10, H15 and H16 harness documents.
ERA_SHA256 = MappingProxyType({
    "architecture/run-events/README.md": "b970b144f9770cb94946ea6baf72bfb3eb9f630384debc41e5a98437df471ddb",
    "architecture/run-events/mas-metrics.schema.json": "da5a18a006868ec80ad66480e97f0e27cd6723eee88aebd128e1014a8e8d4e62",
    "architecture/run-events/mast-annotation.schema.json": "fb580572b3281430d6482173438b58ff9e10cf877b414083d4aefe7d1dd85828",
    "architecture/run-events/review-round1.json": "b4f4b48bbd561ec82bbd5f873ea3785724bb5945c09cfde47a6d1432ada681ef",
    "architecture/run-events/review-round2.json": "bc7d6ea733d4424e581e0f37039310ec7be36c8451b0978a494af53f258f18c9",
    "architecture/run-events/review-round3.json": "a2ed3853df082695146ab1e2e950fefc7b4afd4bee6eb9d236bf45a22eedc8f9",
    "architecture/run-events/round1/README.md": "38c8e4df30676d45cf71578c897aa691036cf1e3ee9e15fba8bf8d59da43c278",
    "architecture/run-events/round1/mas-metrics.schema.json": "38ef430f7412f4fb0bc69e61d50e490e0d3a203c9f3d4f9c91a1985610b24382",
    "architecture/run-events/round1/mast-annotation.schema.json": "606b76b729eedbea82cb1c9066b065100b7bd0c004c68ac738484bcc2fc38b7d",
    "architecture/run-events/round1/run-event-log.schema.json": "0e33a91b6251ef0f0d62a39131e175980653738263f08d1af4c3caa339937555",
    "architecture/run-events/round1/scripts/run_events.py": "10b55b3f89c039f2bafb2c978f4247e06b66871016df9a57f3b9d0b0c537f466",
    "architecture/run-events/round2/README.md": "be958fbdcc1adcc22680e241d3df1fd609d27bad9e5d83ea5bdda30e4d52d1c5",
    "architecture/run-events/round2/mas-metrics.schema.json": "da5a18a006868ec80ad66480e97f0e27cd6723eee88aebd128e1014a8e8d4e62",
    "architecture/run-events/round2/mast-annotation.schema.json": "fb580572b3281430d6482173438b58ff9e10cf877b414083d4aefe7d1dd85828",
    "architecture/run-events/round2/run-event-log.schema.json": "9d0f184ff1240775ba579ebf1b76c2662e5f96f941f223b2eb3159a7abc71024",
    "architecture/run-events/round2/scripts/run_events.py": "2e59820e65c693a5f60df714dd890eaccf02eb506d9c8673f1f369716cce14ad",
    "architecture/run-events/run-event-log.schema.json": "9d0f184ff1240775ba579ebf1b76c2662e5f96f941f223b2eb3159a7abc71024",
    "architecture/run-events/status.json": "c5a6c69cd18dd064fbab6cd4016ec8a2cd55421ee62c5a674a3d349cb7e63664",
    "architecture/run-events/vectors.json": "28061288e5c6cce5d8c10c080ecad3517873d5ab818f6bb285e7d1e775adf9a2",
    "docs/harnesses/execution.orchestration.md": "d54d2937d78bc78984a524fdf7769ec10d8e13ff5d3102881d1d5372533c79e3",
    "docs/harnesses/trust.evaluation-assurance.md": "57b73641ad2362dd31948d57ab810f76f6f5285a254545fe1a7f031b160e860c",
    "docs/harnesses/trust.observability-finops.md": "25e0be5e61350cf1ab00ab3abd654b678d4d48bed8dfad8d3d0e1fe5efe09aee",
    "scripts/agent_loop.py": "f9a1fb1441a39efa6e566b26474f25f30106e4bbf6be4919d31ac69dddc48e68",
    "scripts/run_events.py": "3a6a138071dfafe52a471c5bc2d86cea6730e7008e843025393b8301656c49ef"
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused."""
    raw = reviewed_bytes(path)
    expected = ERA_SHA256.get(path)
    require(expected is not None and digest(raw) == expected, "MAS-RA-003 reviewed bytes are bound: " + path)
    return raw


def _json(path: str) -> Any:
    return parse(_verified(path))


def _bound(check: Any, message: str) -> None:
    """A structural check over a module's result or a record; a malformed one is refused, not raised."""
    try:
        holds = check()
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        holds = False
    require(holds is True, message)


def _era_model(path: str, name: str) -> types.ModuleType:
    """A reference module of this era, executed from its verified bytes."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    exec(compile(_verified(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def validate_era_bytes() -> None:
    """Every reviewed file of this era is bound by digest before anything is parsed or executed; the harness documents,
    the agent-loop contract and model, and the schemas are frozen: no changed or new file under them."""
    for path in list(_PROJECTION_RULES) + list(authority()["newFiles"]):
        require(path not in FROZEN_PATHS and not path.startswith(FROZEN_PREFIXES),
                "the harness documents, the agent-loop contract and the repository schemas stay byte-identical")
    for path, expected in ERA_SHA256.items():
        require(digest(reviewed_bytes(path)) == expected, "MAS-RA-003 reviewed bytes are bound: " + path)


def validate_run_events_status() -> None:
    """Adopted after independent review rounds, each bound to its record; the last passed this subject with NOTE findings
    only, each carried; every earlier round is snapshotted; the README's status line is the one adoption edit."""
    status = _json(STATUS_PATH)
    require(type(status) is dict and set(status) == set(STATUS_KEYS)
            and status["schemaVersion"] == "planeon.internal.run-events-status/v1"
            and status["workItem"] == "MAS-RA-003" and status["status"] == "ADOPTED_CONTRACT_CANDIDATE"
            and status["contract"] == CONTRACT and status["reviewedSubject"] == REVIEWED_SUBJECT
            and status["acceptance"] == ACCEPTANCE and status["ownerDecisions"] == DECISIONS
            and status["nonClaims"] == NON_CLAIMS and type(status["carried"]) is list
            and all(type(row) is dict and set(row) == {"item", "severity", "to", "action"} for row in status["carried"]),
            "adopted MAS-RA-003 status")
    readme = _verified(README_PATH).decode("utf-8")
    edit = status["adoptionEdit"]
    _bound(lambda: edit == {"path": README_PATH, "replaced": STATUS_LINE[0], "with": STATUS_LINE[1],
                            "reviewedSha256": edit["reviewedSha256"], "adoptedSha256": ERA_SHA256[README_PATH]}
           and readme.count(STATUS_LINE[1]) == 1 and STATUS_LINE[0] not in readme
           and digest(readme.replace(STATUS_LINE[1], STATUS_LINE[0]).encode("utf-8")) == edit["reviewedSha256"],
           "the README's status line is the one adoption edit")
    rounds = status["rounds"]
    previous: list = []
    require(type(rounds) is list and all(type(row) is dict for row in rounds)
            and [(row.get("round"), row.get("verdict")) for row in rounds] == list(ROUNDS), "review rounds in order")
    for row in rounds:
        number = row["round"]
        earlier = number < LAST_ROUND
        require(set(row) == set(ROW_KEYS) | ({"digestOnly"} if earlier else set())
                and row["record"] == CONTRACT_DIR + "review-round%d.json" % number
                and row["snapshot"] == (CONTRACT_DIR + "round%d/" % number if earlier else None),
                "review round %d row" % number)
        if earlier:
            _bound(lambda: set(row["digestOnly"]) == {VECTORS_PATH}
                   and type(row["digestOnly"][VECTORS_PATH]) is str and len(row["digestOnly"][VECTORS_PATH]) == 64
                   and set(row["digestOnly"][VECTORS_PATH]) <= set("0123456789abcdef")
                   and row["digestOnly"][VECTORS_PATH] != ERA_SHA256[VECTORS_PATH]
                   and all(CONTRACT_DIR + "round%d/" % number + name in ERA_SHA256 for name in SNAPSHOT_FILES),
                   "review round %d snapshot" % number)
        record = _json(row["record"])
        require(type(record) is dict and record.get("schemaVersion") == REVIEW_SCHEMA and record.get("round") == number
                and record.get("subjectCommit") == row["subject"] and record.get("subjectTree") == row["subjectTree"]
                and record.get("verdict") == row["verdict"], "review round %d identity" % number)
        actions = record.get("actions")
        require(type(actions) is dict and actions.get("filesEdited") is False and actions.get("personalDataSent") is False
                and actions.get("networkAccessed") == "none",
                "review round %d edited nothing, used no network and sent no personal data" % number)
        findings = record.get("findings")
        dispositions = record.get("dispositions")
        require(type(findings) is list and all(type(item) is dict and item.get("severity") in SEVERITIES for item in findings)
                and row["severities"] == sorted({item["severity"] for item in findings})
                and type(dispositions) is list
                and all(type(item) is dict and "disposition" in item and "finding" in item for item in dispositions)
                and (number > 1 or dispositions == []), "review round %d severities and dispositions" % number)
        if number > 1:   # every finding of the previous round has a recorded disposition
            require({item.get("id") for item in previous} <= {item.get("finding") for item in dispositions},
                    "review round %d disposes of every round %d finding" % (number, number - 1))
        previous = findings
    final = rounds[-1]
    require(final["subject"] == REVIEWED_SUBJECT["commit"] and final["subjectTree"] == REVIEWED_SUBJECT["tree"]
            and final["verdict"] == "PASS_FOR_SOURCE_PUBLICATION" and set(final["severities"]) <= {"NOTE"},
            "the final round passed this subject with NOTE findings only")
    _bound(lambda: [(row["item"], row["severity"], row["to"], row["action"]) for row in status["carried"]]
           == [(item["id"], item["severity"], CARRIED_TO, item["requiredChange"]) for item in previous],
           "every finding of the final round is carried")


def _outcome(model: types.ModuleType, call: Any) -> Any:
    try:
        call()
    except model.Refused as refusal:
        return refusal.code
    return None


def validate_run_events_contract() -> None:
    """The contract's model from this era's bytes, given this era's agent-loop model, replays every vector and OTel
    projection; the codes, schema identities, metrics, MAST and OTel sources and the counts are restated here."""
    loop = _era_model(LOOP_MODEL, "_met_mas_003_agent_loop")
    model = _era_model(MODEL, "_met_mas_003_run_events")
    vectors = _json(VECTORS_PATH)
    schemas = {name: _json(CONTRACT_DIR + name) for name in SCHEMA_FILES}
    _bound(lambda: vectors["schemaVersion"] == VECTORS_SCHEMA and vectors["evidenceClass"] == "DATA_CHECK_ONLY",
           "the vectors' identity")
    _bound(lambda: tuple(model.LOG_CODES) == LOG_CODES and tuple(vectors["logCodes"]) == LOG_CODES
           and tuple(model.METRIC_CODES) == METRIC_CODES and tuple(vectors["metricCodes"]) == METRIC_CODES
           and tuple(model.ANNOTATION_CODES) == ANNOTATION_CODES
           and tuple(vectors["annotationCodes"]) == ANNOTATION_CODES, "the refusal codes in their order")
    _bound(lambda: all(schemas[name]["$id"] == SCHEMA_IDS[name] for name in SCHEMA_FILES)
           and [model.LOG_SCHEMA, model.METRICS_SCHEMA, model.ANNOTATION_SCHEMA]
           == [SCHEMA_IDS[name] for name in SCHEMA_FILES], "the three schema identities")
    _bound(lambda: tuple(model.METRICS) == METRICS
           and [(row["name"], row["unit"]) for row in vectors["metrics"]] == list(METRICS),
           "the eighteen metrics and their units (Q-MAS3-E)")
    _bound(lambda: model.MAST_SOURCE["sha256"] == MAST_SHA256 and vectors["mastSource"] == model.MAST_SOURCE
           and tuple((mode[0], mode[2]) for mode in model.MAST_MODES) == MAST_MODES
           and [(row["id"], row["category"]) for row in vectors["mastModes"]] == list(MAST_MODES),
           "the MAST source and its fourteen modes (Q-MAS3-F)")
    _bound(lambda: model.OTEL_SOURCE["commit"] == OTEL_COMMIT and model.OTEL_SOURCE["files"] == OTEL_FILES
           and vectors["otelSource"] == model.OTEL_SOURCE, "the pinned OTel GenAI source (Q-MAS3-D)")
    stores = vectors["stores"]
    checks = {"log": lambda d: model.check_log(d, stores, loop), "report": lambda d: model.check_report(d, stores, loop),
              "annotation": lambda d: model.check_annotation(d, stores, loop)}
    kinds = (("log", LOG_CODES), ("report", METRIC_CODES), ("annotation", ANNOTATION_CODES))
    _bound(lambda: {"cases": len(vectors["cases"]), "valid": sum(1 for row in vectors["cases"] if row["expect"] is None),
                    "texts": len(vectors["texts"]), "otelProjections": len(vectors["otelProjections"]),
                    "logs": len(stores["logs"]), "traces": len(stores["traces"]),
                    "manifests": len(stores["manifests"])} == VECTOR_COUNTS
           and all({row["expect"] for row in vectors["cases"] if row["kind"] == kind} - {None} == set(codes)
                   for kind, codes in kinds), "the vector counts, every code covered")
    for row in vectors["cases"]:
        facts: list = []
        got = _outcome(model, lambda: facts.append(checks[row["kind"]](row["document"])))
        _bound(lambda: got == row["expect"] and (not facts or "facts" not in row
               or {k: facts[0][k] for k in row["facts"]} == row["facts"]), "case " + str(row.get("id")))
    for row in vectors["texts"]:
        _bound(lambda: _outcome(model, lambda: checks[row["kind"]](model.parse(row["text"]))) == row["expect"],
               "text " + str(row.get("id")))
    for row in vectors["otelProjections"]:
        _bound(lambda: model.to_otel(stores["logs"][row["log"]]) == row["spans"], "OTel projection " + str(row.get("log")))


def validate_run_events() -> None:
    """Every reviewed byte and the adoption record first; then the contract from this era."""
    validate_era_bytes()
    validate_run_events_status()
    validate_run_events_contract()


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "run events validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 240
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 240-packet catalog retaining the 233-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only run-events packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted run-events packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_run_events()


if __name__ == "__main__":
    validate()
    print("Run events valid: 240 current specifications; 233-packet checkpoint and exact 232-packet predecessor; contract reviewed.")
