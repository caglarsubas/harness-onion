#!/usr/bin/env python3
"""Validate the MET-PERF-040 chain-depth headroom and the exact 241-to-240 projection."""
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
    import validate_i05_gate_channel_v4 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_i05_gate_channel_v4 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/chain-depth-headroom-authority.json"
AUTHORITY_SHA256 = "3c6d5d1d632704f5c88c0098bf1dd7c51563ef115a777c10346077e180854da1"
VALIDATOR_PATH = "scripts/validate_chain_depth_headroom.py"
BASE_COMMIT = "d2ef7083d241a6bc1adb8ef923cc558d550fcd2b"
NEW_PACKET = "MET-PERF-040"
PREVIOUS_PACKET = "MET-ENFORCE-029"
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
            require(key not in result, "duplicate chain-depth-headroom authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite chain-depth-headroom authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "chain-depth headroom history authority digest")
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
    }, "closed chain-depth headroom history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/chain-depth-headroom-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 240
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 240-packet base")
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
    # An exact 240-era byte string is already older than the successor layer.
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


# MET-PERF-040 (roadmap PERF-040; owner decisions PERF-040-FIRST and Q-PERF40-1..3, 2026-10-16, and the lane monitor's
# owner-delegated Q-PERF40-4) gives back verify headroom lost to the history chain's depth, without changing any
# validator's freshness rule: every route still reads its authority fresh. Four changes, bound here by digest:
# - tests/conftest.py shares repeated identical history projections within one test (exact str/bytes arguments only,
#   refusals never memoised, each wrapper bound to its own test's memo), except for the pinned never-shared tests;
# - this packet's authority uses canonical byte-minimal reverse hunks, which this layer recomputes from its own era's
#   bytes and requires exactly (a carried rule for every later layer);
# - the parallel suite's weights are refreshed for all 127 test files (the worker count stays six);
# - the matrix v5 layer's replay_v5_vectors runs its identifier and position checks before the replay (239's P2-1).
# Repository bytes are read only through reviewed_bytes, so a later bridged successor projects its own edits away first.
# Every input of this era is bound by digest before it is parsed; the record is checked against the conftest, the
# weights and this layer's own inverse.
CONTRACT_DIR = "architecture/chain-depth-headroom/"
README = CONTRACT_DIR + "README.md"
REVIEW_BRIEF = CONTRACT_DIR + "REVIEW_BRIEF.md"
RECORD = CONTRACT_DIR + "record.json"
CONFTEST = "tests/conftest.py"
WEIGHTS = "ci/parallel_suite_weights.json"
MATRIX_LAYER = "scripts/validate_selinux_matrix_v3.py"
MATRIX_TEST = "tests/test_selinux_matrix_v3.py"
# The contract files and the conftest are new here; the weights and the two matrix files change here.
NEW_CONTRACT = (README, REVIEW_BRIEF, RECORD, CONFTEST)
ERA_SHA256 = MappingProxyType({
    "architecture/chain-depth-headroom/README.md": "c07ffdcfb86fbe9f5678507ddbc8e14671d4ee36c82e365cfbae696b2a1de733",
    "architecture/chain-depth-headroom/REVIEW_BRIEF.md": "3765479f7f04045fa7d00da8afcbefd7e197a8ca5da3c49944c83c8576dd87b1",
    "architecture/chain-depth-headroom/record.json": "c173e49263cc429abb21c6c08ccc72daa13a1f6571fa2b84c0f4b80a1377c60c",
    "ci/parallel_suite_weights.json": "4b23112661d8ed592474fea16ced62c1bf94c99e7bfd23c113797a5299ab0b45",
    "scripts/validate_selinux_matrix_v3.py": "21ea60feee05b2007300fb13591a1953c69190680bf5f1c6b430fd76a80feb9d",
    "tests/conftest.py": "d4c9542ca315b5e585f2196189bcc86d76739740e9d2fa58b60a37ecdaf3b6af",
})
WEIGHTS_BEFORE_SHA256 = "2c1b27f6281e996accbcbc43169dec2041676f1831b0c2e02cb8e09a3395ec3f"
WEIGHT_FILES = (
    "ci/test_offline_runner.py",
    "ci/test_warm_snapshot.py",
    "tests/linux_runner/test_authority.py",
    "tests/linux_runner/test_build_and_predecessors.py",
    "tests/linux_runner/test_isolation.py",
    "tests/linux_runner/test_manifest_gate.py",
    "tests/linux_runner/test_predecessor_diagnostics.py",
    "tests/linux_runner/test_predecessor_proof.py",
    "tests/linux_runner/test_system_inventory_v2.py",
    "tests/linux_runner/test_toolchain.py",
    "tests/linux_runner/test_workspace_v2.py",
    "tests/test_accounting_scope.py",
    "tests/test_admission_channel_v3.py",
    "tests/test_admission_semantics_v2.py",
    "tests/test_agent_loop.py",
    "tests/test_alpha2_readiness.py",
    "tests/test_architecture.py",
    "tests/test_authority_recheck_reuse.py",
    "tests/test_backend_distribution.py",
    "tests/test_backend_timing.py",
    "tests/test_benchmark_transport.py",
    "tests/test_broker_handoff.py",
    "tests/test_canonical_repair_plan.py",
    "tests/test_catalog_traversal.py",
    "tests/test_ci_performance.py",
    "tests/test_ci_runner_admission.py",
    "tests/test_compiled_filter_programs.py",
    "tests/test_compiled_filter_programs_v2.py",
    "tests/test_completion_integration.py",
    "tests/test_completion_profiling.py",
    "tests/test_conformance_completion.py",
    "tests/test_conformance_consumer_closure.py",
    "tests/test_conformance_performance.py",
    "tests/test_conformance_performance_followup.py",
    "tests/test_conformance_publication.py",
    "tests/test_conformance_reference_measurement.py",
    "tests/test_conformance_successor_checkpoint.py",
    "tests/test_credential_lifecycle.py",
    "tests/test_credential_ordering.py",
    "tests/test_custody_handoff.py",
    "tests/test_data_harness_v1_observation.py",
    "tests/test_dedicated_verifier_account.py",
    "tests/test_diagnostic_repair.py",
    "tests/test_document_repair_execution.py",
    "tests/test_document_repair_plan.py",
    "tests/test_enforcement_integration.py",
    "tests/test_enforcement_test_plan.py",
    "tests/test_factory_diagnostics.py",
    "tests/test_guard_cost_repair.py",
    "tests/test_guard_traversal.py",
    "tests/test_historical_snapshot_decode.py",
    "tests/test_host_interface.py",
    "tests/test_host_interface_hs43.py",
    "tests/test_host_interface_resolution.py",
    "tests/test_i05_gate_channel.py",
    "tests/test_i05_gate_channel_v2.py",
    "tests/test_i06_backend_profile.py",
    "tests/test_i06_backend_profile_v2.py",
    "tests/test_i07_policy_write.py",
    "tests/test_i07_policy_write_v2.py",
    "tests/test_in_session_predecessor_proof.py",
    "tests/test_isolated_network_canary.py",
    "tests/test_isolated_offline_runner.py",
    "tests/test_license_amendment.py",
    "tests/test_linear_history_rechecks.py",
    "tests/test_linux_readiness.py",
    "tests/test_linux_repair.py",
    "tests/test_linux_runner_contract.py",
    "tests/test_linux_test_ownership.py",
    "tests/test_live_backend_readiness.py",
    "tests/test_live_campaign_envelope.py",
    "tests/test_load_deadlines.py",
    "tests/test_local_acceptance.py",
    "tests/test_model_api_inventory.py",
    "tests/test_model_fixture_scope.py",
    "tests/test_model_usage_observation.py",
    "tests/test_native_profile_v2.py",
    "tests/test_native_profile_v3.py",
    "tests/test_native_qualification.py",
    "tests/test_observation_enforcement.py",
    "tests/test_owner_verifier.py",
    "tests/test_packet_declaration_consistency.py",
    "tests/test_packet_scalar_repair.py",
    "tests/test_packet_schema_performance.py",
    "tests/test_packet_semantic_reuse.py",
    "tests/test_parallel_suite.py",
    "tests/test_parallel_suite_followup.py",
    "tests/test_policy_observation.py",
    "tests/test_portable_warm_snapshot_temp.py",
    "tests/test_projection_reuse.py",
    "tests/test_provider_adoption.py",
    "tests/test_proxy_contract.py",
    "tests/test_proxy_diagnostics.py",
    "tests/test_pytest_diagnostics.py",
    "tests/test_pytest_headroom.py",
    "tests/test_readiness.py",
    "tests/test_readiness_repairs.py",
    "tests/test_reference_observer.py",
    "tests/test_release_lock.py",
    "tests/test_repository_tree_observation.py",
    "tests/test_research_adoption.py",
    "tests/test_research_adoption_v2.py",
    "tests/test_research_adoption_v3.py",
    "tests/test_reuse.py",
    "tests/test_run_events.py",
    "tests/test_run_manifest.py",
    "tests/test_seccomp_allowlists.py",
    "tests/test_seccomp_v3.py",
    "tests/test_seccomp_v4.py",
    "tests/test_sector_catalog.py",
    "tests/test_sector_direction.py",
    "tests/test_selinux_matrix.py",
    "tests/test_selinux_matrix_v2.py",
    "tests/test_selinux_matrix_v3.py",
    "tests/test_selinux_replay.py",
    "tests/test_source_recipe_projection.py",
    "tests/test_successor_inventory.py",
    "tests/test_task_packets.py",
    "tests/test_unified_roadmap.py",
    "tests/test_validation_performance.py",
    "tests/test_validator_units.py",
    "tests/test_verdict_ledger.py",
    "tests/test_verify_headroom.py",
    "tests/test_w01_amendment.py",
    "tests/test_w02_notes_errata.py",
    "tests/test_w03_amendment.py",
    "tests/test_zero_bill.py",
)
NEVER_SHARED = frozenset({
    "test_each_locked_input_is_checked_and_unknown_or_missing_files_refuse",
    "test_each_projection_freshly_rechecks_complete_authority",
    "test_each_protected_input_rechecked_not_cached",
    "test_every_input_pin_is_enforced",
    "test_every_newer_authority_is_read_exactly_once_per_route",
    "test_every_projection_rechecks_actual_authority_bytes",
    "test_freshness_only_routes_read_full_authority_without_reparsing",
    "test_full_predecessor_suites_and_validators_remain_green",
    "test_history_routes_still_refuse_second_call_authority_drift",
    "test_newest_authority_is_freshly_checked_on_every_route",
    "test_performance_predecessor_and_exact_twenty_commands",
    "test_real_projection_refuses_authority_drift_even_with_warm_conversion",
    "test_schema_performance_authority_is_rechecked_through_every_history_route",
    "test_warm_conversion_still_runs_fresh_interleaved_integrity",
    "test_warm_success_then_current_packet_map_drift_still_refuses",
})
DECISION_IDS = ("PERF-040-FIRST", "Q-PERF40-1..3", "Q-PERF40-4")
RECORD_KEYS = ("schemaVersion", "workItem", "baseMain", "evidenceClass", "ownerDecisions", "testSharing",
               "authorityHunks", "weights", "replayOrder", "measurements", "notClaimed")
WORKERS = 6


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _verified(path: str) -> bytes:
    """The reviewed bytes of one bound input, checked against its era digest before any use (era membership first)."""
    require(path in ERA_SHA256, "MET-PERF-040 reviewed bytes are bound: " + path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == ERA_SHA256[path], "unreviewed chain-depth-headroom source: " + path)
    return raw


def _text(path: str) -> str:
    raw = _verified(path)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("chain-depth-headroom source is not UTF-8: " + path) from exc


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


def _never_shared(conftest: str) -> frozenset:
    tree = ast.parse(conftest, CONFTEST)
    found = [node.value for node in tree.body if isinstance(node, ast.Assign)
             and [getattr(target, "id", None) for target in node.targets] == ["NEVER_SHARED"]]
    require(len(found) == 1 and isinstance(found[0], ast.Call) and getattr(found[0].func, "id", None) == "frozenset"
            and len(found[0].args) == 1 and isinstance(found[0].args[0], ast.Set), "one literal never-shared set")
    names = [ast.literal_eval(element) for element in found[0].args[0].elts]
    require(len(names) == len(set(names)) and all(type(name) is str for name in names), "distinct never-shared names")
    return frozenset(names)


def validate_chain_depth_headroom() -> None:
    """The four changes against their record, the conftest, the weights and this layer's own inverse."""
    for path in ERA_SHA256:
        _verified(path)
    for path in (README, REVIEW_BRIEF):
        _text(path)
    record = parse(_verified(RECORD))
    require(type(record) is dict and tuple(record) == RECORD_KEYS and record["schemaVersion"]
            == "planeon.internal.chain-depth-headroom/v1" and record["baseMain"] == BASE_COMMIT
            and [row["id"] for row in record["ownerDecisions"]] == list(DECISION_IDS), "closed chain-depth-headroom record")
    sharing = record["testSharing"]
    conftest = _text(CONFTEST)
    require(sharing["conftest"] == {"path": CONFTEST, "sha256": ERA_SHA256[CONFTEST]}
            and _never_shared(conftest) == NEVER_SHARED == frozenset(row["name"] for row in sharing["neverShared"])
            and len(sharing["neverShared"]) == len(NEVER_SHARED) and sharing["sharedFunction"] == "historical_bytes"
            and sharing["refusalsMemoised"] is False and sharing["sharingChangesValidators"] is False
            and "def _exact_history_sharing(request):" in conftest and "@pytest.fixture(autouse=True)" in conftest,
            "the conftest shares exactly as recorded, never the pinned tests")
    weights_raw = _verified(WEIGHTS)
    weights = parse(weights_raw)
    require(type(weights) is dict and list(weights) == sorted(weights) and set(weights) == set(WEIGHT_FILES)
            and all(type(value) is float and value >= 0 and round(value, 1) == value for value in weights.values())
            and digest(_undo_this_layer(WEIGHTS, weights_raw)) == WEIGHTS_BEFORE_SHA256
            and record["weights"]["afterSha256"] == ERA_SHA256[WEIGHTS]
            and record["weights"]["beforeSha256"] == WEIGHTS_BEFORE_SHA256
            and record["weights"]["files"] == len(WEIGHT_FILES) and record["weights"]["workers"] == WORKERS,
            "refreshed weights for every test file; six workers")
    layer = _text(MATRIX_LAYER)
    start = layer.index("def replay_v5_vectors(")
    body = layer[start:layer.index("\ndef ", start + 1)]
    position = body.find('"every v4 %s vector is kept at its position; only the listed ones change" % key)')
    replay = body.find('    for row in vectors["accessChecks"]:')
    require(0 < position < replay and body.count('for row in vectors["accessChecks"]:') == 1,
            "the identifier and position checks run before the replay (P2-1)")
    require(MATRIX_LAYER in _PROJECTION_RULES and MATRIX_TEST in _PROJECTION_RULES and WEIGHTS in _PROJECTION_RULES
            and not any(path in _PROJECTION_RULES for path in NEW_CONTRACT), "the changed and the new files")
    validate_canonical_hunks()


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "chain-depth headroom validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 243
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET},
            "closed 243-packet catalog retaining the 241-packet checkpoint")
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
            "closed source-only chain-depth-headroom packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted chain-depth-headroom packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_chain_depth_headroom()


if __name__ == "__main__":
    validate()
    print("Chain-depth headroom valid: 243 current specifications; 241-packet checkpoint and exact 240-packet predecessor; source reviewed.")
