"""Exact source lineage for MET-ENFORCE-029; compiled filter programs v2: EFFECT_GATE republished from seccomp allowlists v4, and edge record v3."""
import ast
import json
import copy
from copy import deepcopy
import os
import re
import stat
from pathlib import Path
from types import MappingProxyType

import pytest

from scripts import validate_compiled_filter_programs_v2 as profile
from scripts import validate_selinux_matrix_v3 as smx
from scripts import validate_pytest_headroom as phr
from scripts import validate_seccomp_v4 as sv4
from scripts import validate_host_interface_hs43 as hs43
from scripts import validate_research_adoption_v3 as rav3
from scripts import validate_load_deadlines as deadlines
from scripts import validate_run_events as events
from scripts import validate_compiled_filter_programs as filters
from scripts import validate_agent_loop as loop
from scripts import validate_run_manifest as manifest
from scripts import validate_verdict_ledger as ledger
from scripts import validate_research_adoption_v2 as adoption
from scripts import validate_w03_amendment as amendment
from scripts import validate_parallel_suite_followup as bprofile
from scripts import validate_w02_notes_errata as mprofile
from scripts import validate_enforcement_test_plan as eprofile
from scripts import validate_license_amendment as lprofile
from scripts import validate_seccomp_v3 as fprofile
from scripts import validate_backend_distribution as oprofile
from scripts import validate_w01_amendment as uprofile
from scripts import validate_seccomp_allowlists as jprofile
from scripts import validate_sector_catalog as kprofile
from scripts import validate_selinux_replay as tprofile
from scripts import validate_parallel_suite as zprofile
from scripts import validate_selinux_matrix_v2 as yprofile
from scripts import validate_admission_channel_v3 as xprofile
from scripts import validate_i07_policy_write_v2 as pprofile
from scripts import validate_admission_semantics_v2 as aprofile
from scripts import validate_i06_backend_profile_v2 as vprofile
from scripts import validate_i05_gate_channel_v2 as cprofile
from scripts import validate_native_profile_v3 as qprofile
from scripts import validate_verify_headroom as hprofile
from scripts import validate_sector_direction as dprofile
from scripts import validate_selinux_matrix as sprofile
from scripts import validate_i07_policy_write as wprofile
from scripts import validate_projection_reuse as rprofile
from scripts import validate_i05_gate_channel as gprofile
from scripts import validate_i06_backend_profile as iprofile
from scripts import validate_native_profile_v2 as nprofile
from scripts import validate_host_interface_resolution as resolution
from scripts import validate_dedicated_verifier_account as account
from scripts import validate_isolated_network_canary as canary
from scripts import validate_isolated_offline_runner as isolated
from scripts import validate_portable_warm_snapshot_temp as portable
from scripts import validate_in_session_predecessor_proof as proof
from scripts import validate_linear_history_rechecks as recheck
from scripts import validate_owner_verifier as verifier
from scripts import validate_linux_runner_contract as linux
from scripts import validate_packet_schema_performance as performance
from scripts import validate_ci_runner_admission as runner
from scripts import validate_unified_roadmap as roadmap
from scripts.safe_yaml import safe_load


def packets():
    return {path.stem: safe_load(path.read_bytes())
            for path in (profile.ROOT / "task-packets").glob("*.yaml")}


def layer_packets():
    # The newer MET-PERF-040 layer is projected away before this layer's payload checks.
    return profile.successor.historical_catalog(packets())


def changed_test():
    return next(path for path in profile._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert profile.validate() is None
    current = packets()
    accepted = profile.historical_catalog(current)
    assert len(current) == 265 and len(accepted) == 239
    assert set(accepted) == set(current) - {profile.NEW_PACKET, profile.successor.NEW_PACKET,
                                            profile.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET}
    assert len(smx.historical_catalog(current)) == 238
    assert len(phr.historical_catalog(current)) == 237
    assert len(sv4.historical_catalog(current)) == 236
    assert len(hs43.historical_catalog(current)) == 235
    assert len(rav3.historical_catalog(current)) == 234
    assert len(deadlines.historical_catalog(current)) == 233
    assert len(events.historical_catalog(current)) == 232
    assert len(filters.historical_catalog(current)) == 231
    assert len(loop.historical_catalog(current)) == 230
    assert len(manifest.historical_catalog(current)) == 229
    assert len(ledger.historical_catalog(current)) == 228
    assert len(adoption.historical_catalog(current)) == 227
    assert len(amendment.historical_catalog(current)) == 226
    assert len(bprofile.historical_catalog(current)) == 225
    assert len(mprofile.historical_catalog(current)) == 224
    assert len(eprofile.historical_catalog(current)) == 223
    assert len(lprofile.historical_catalog(current)) == 222
    assert len(fprofile.historical_catalog(current)) == 221
    assert len(oprofile.historical_catalog(current)) == 220
    assert len(uprofile.historical_catalog(current)) == 219
    assert len(jprofile.historical_catalog(current)) == 218
    assert len(kprofile.historical_catalog(current)) == 217
    assert len(tprofile.historical_catalog(current)) == 216
    assert len(zprofile.historical_catalog(current)) == 215
    assert len(yprofile.historical_catalog(current)) == 214
    assert len(xprofile.historical_catalog(current)) == 213
    assert len(pprofile.historical_catalog(current)) == 212
    assert len(aprofile.historical_catalog(current)) == 211
    assert len(vprofile.historical_catalog(current)) == 210
    assert len(cprofile.historical_catalog(current)) == 209
    assert len(qprofile.historical_catalog(current)) == 208
    assert len(hprofile.historical_catalog(current)) == 207
    assert len(dprofile.historical_catalog(current)) == 206
    assert len(sprofile.historical_catalog(current)) == 205
    assert len(wprofile.historical_catalog(current)) == 204
    assert len(rprofile.historical_catalog(current)) == 203
    assert len(gprofile.historical_catalog(current)) == 202
    assert len(iprofile.historical_catalog(current)) == 201
    assert len(nprofile.historical_catalog(current)) == 200
    assert len(resolution.historical_catalog(current)) == 199
    assert len(account.historical_catalog(current)) == 198
    assert len(canary.historical_catalog(current)) == 197
    assert len(isolated.historical_catalog(current)) == 196
    assert len(portable.historical_catalog(current)) == 195
    assert len(proof.historical_catalog(current)) == 194
    assert len(recheck.historical_catalog(current)) == 193
    assert len(verifier.historical_catalog(current)) == 192
    assert len(linux.historical_catalog(current)) == 191
    assert len(performance.historical_catalog(current)) == 190
    assert len(runner.historical_catalog(current)) == 189
    assert len(roadmap.historical_catalog(current)) == 188
    for name, expected in profile.authority()["baselinePackets"].items():
        assert profile.digest(profile.regular_bytes("task-packets/" + name + ".yaml")) == expected
    for path, rule in profile._PROJECTION_RULES.items():
        raw = profile.successor.historical_bytes(path, profile.regular_bytes(path))
        assert profile.digest(raw) == rule["afterSha256"]
        before = profile.historical_bytes(path, raw)
        assert profile.digest(before) == rule["beforeSha256"]
        assert profile.historical_bytes(path, before) == before


@pytest.mark.parametrize("fault", ["missing_new", "missing_old", "extra", "new_payload", "old_payload", "projected"])
def test_catalog_refuses_all_packet_substitution_and_loss(fault):
    current = deepcopy(layer_packets())
    if fault == "missing_new":
        current.pop(profile.NEW_PACKET)
    elif fault == "missing_old":
        current.pop("MET-RUNNER-001")
    elif fault == "extra":
        current["UNREVIEWED-001"] = {}
    elif fault == "projected":
        current = profile.historical_catalog(deepcopy(packets()))
    else:
        name = profile.NEW_PACKET if fault == "new_payload" else "MET-001"
        current[name]["objective"] += " unreviewed"
    with pytest.raises(ValueError):
        profile.validate_packet_payloads(current)


def test_every_predecessor_payload_is_checked_without_a_verdict_cache():
    current = layer_packets()
    profile.validate_packet_payloads(current)
    for name in sorted(profile.authority()["baselinePackets"])[:1]:
        original = current[name]
        current[name] = dict(original, objective=original["objective"] + " unreviewed")
        with pytest.raises(ValueError, match="changed packet payload"):
            profile.validate_packet_payloads(current)
        current[name] = original
    # MET-PERF-042 (C2): this layer's payload table against digests this test computes from the disk YAML.
    import hashlib
    import json
    table = profile._packet_rules()
    assert set(table) == set(profile.authority()["baselinePackets"]) | {profile.NEW_PACKET}
    for name in sorted(table):
        raw = (profile.ROOT / "task-packets" / (name + ".yaml")).read_bytes()
        payload = json.dumps(safe_load(raw), sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                             allow_nan=False).encode("utf-8")
        assert table[name] == (hashlib.sha256(raw).hexdigest(), hashlib.sha256(payload).hexdigest()), name


def test_acceptance_retains_every_inherited_command_and_wrapper():
    current = packets()
    packet, predecessor = current[profile.NEW_PACKET], current[profile.PREVIOUS_PACKET]
    commands = packet["offlineAcceptanceCommands"]
    assert len(commands) == 64 and commands == predecessor["offlineAcceptanceCommands"]
    assert not any(profile.VALIDATOR_PATH in argv for argv in commands)
    assert commands[-2][-3:] == ["tests", "ci/test_offline_runner.py", "ci/test_warm_snapshot.py"]
    assert packet["offlineExecution"] == predecessor["offlineExecution"]
    assert packet["sourceReuse"] == packet["prefetchCommands"] == []
    assert "liveCampaignExecution" not in packet


def test_exact_inverse_and_forward_test_round_trip_across_layers():
    path = changed_test()
    current = profile.regular_bytes(path)
    before = profile.historical_bytes(path, current)
    assert before != current
    assert profile.historical_test_bytes(current) == before
    assert profile.current_test_bytes(before) == current
    assert profile.current_test_bytes(before + b" ") == before + b" "
    smx_before = smx.historical_bytes(path, current)
    assert smx.current_test_bytes(smx_before) == current
    phr_before = phr.historical_bytes(path, current)
    assert phr.current_test_bytes(phr_before) == current
    sv4_before = sv4.historical_bytes(path, current)
    assert sv4.current_test_bytes(sv4_before) == current
    hs43_before = hs43.historical_bytes(path, current)
    assert hs43.current_test_bytes(hs43_before) == current
    rav3_before = rav3.historical_bytes(path, current)
    assert rav3.current_test_bytes(rav3_before) == current
    deadlines_before = deadlines.historical_bytes(path, current)
    assert deadlines.current_test_bytes(deadlines_before) == current
    events_before = events.historical_bytes(path, current)
    assert events.current_test_bytes(events_before) == current
    filters_before = filters.historical_bytes(path, current)
    assert filters.current_test_bytes(filters_before) == current
    loop_before = loop.historical_bytes(path, current)
    assert loop.current_test_bytes(loop_before) == current
    manifest_before = manifest.historical_bytes(path, current)
    assert manifest.current_test_bytes(manifest_before) == current
    ledger_before = ledger.historical_bytes(path, current)
    assert ledger.current_test_bytes(ledger_before) == current
    adoption_before = adoption.historical_bytes(path, current)
    assert adoption.current_test_bytes(adoption_before) == current
    amendment_before = amendment.historical_bytes(path, current)
    assert amendment.current_test_bytes(amendment_before) == current
    bprofile_before = bprofile.historical_bytes(path, current)
    assert bprofile.current_test_bytes(bprofile_before) == current
    mprofile_before = mprofile.historical_bytes(path, current)
    assert mprofile.current_test_bytes(mprofile_before) == current
    eprofile_before = eprofile.historical_bytes(path, current)
    assert eprofile.current_test_bytes(eprofile_before) == current
    lprofile_before = lprofile.historical_bytes(path, current)
    assert lprofile.current_test_bytes(lprofile_before) == current
    fprofile_before = fprofile.historical_bytes(path, current)
    assert fprofile.current_test_bytes(fprofile_before) == current
    oprofile_before = oprofile.historical_bytes(path, current)
    assert oprofile.current_test_bytes(oprofile_before) == current
    uprofile_before = uprofile.historical_bytes(path, current)
    assert uprofile.current_test_bytes(uprofile_before) == current
    jprofile_before = jprofile.historical_bytes(path, current)
    assert jprofile.current_test_bytes(jprofile_before) == current
    kprofile_before = kprofile.historical_bytes(path, current)
    assert kprofile.current_test_bytes(kprofile_before) == current
    tprofile_before = tprofile.historical_bytes(path, current)
    assert tprofile.current_test_bytes(tprofile_before) == current
    zprofile_before = zprofile.historical_bytes(path, current)
    assert zprofile.current_test_bytes(zprofile_before) == current
    yprofile_before = yprofile.historical_bytes(path, current)
    assert yprofile.current_test_bytes(yprofile_before) == current
    xprofile_before = xprofile.historical_bytes(path, current)
    assert xprofile.current_test_bytes(xprofile_before) == current
    pprofile_before = pprofile.historical_bytes(path, current)
    assert pprofile.current_test_bytes(pprofile_before) == current
    aprofile_before = aprofile.historical_bytes(path, current)
    assert aprofile.current_test_bytes(aprofile_before) == current
    vprofile_before = vprofile.historical_bytes(path, current)
    assert vprofile.current_test_bytes(vprofile_before) == current
    cprofile_before = cprofile.historical_bytes(path, current)
    assert cprofile.current_test_bytes(cprofile_before) == current
    qprofile_before = qprofile.historical_bytes(path, current)
    assert qprofile.current_test_bytes(qprofile_before) == current
    hprofile_before = hprofile.historical_bytes(path, current)
    assert hprofile.current_test_bytes(hprofile_before) == current
    dprofile_before = dprofile.historical_bytes(path, current)
    assert dprofile.current_test_bytes(dprofile_before) == current
    sprofile_before = sprofile.historical_bytes(path, current)
    assert sprofile.current_test_bytes(sprofile_before) == current
    wprofile_before = wprofile.historical_bytes(path, current)
    assert wprofile.current_test_bytes(wprofile_before) == current
    rprofile_before = rprofile.historical_bytes(path, current)
    assert rprofile.current_test_bytes(rprofile_before) == current
    gprofile_before = gprofile.historical_bytes(path, current)
    assert gprofile.current_test_bytes(gprofile_before) == current
    iprofile_before = iprofile.historical_bytes(path, current)
    assert iprofile.current_test_bytes(iprofile_before) == current
    nprofile_before = nprofile.historical_bytes(path, current)
    assert nprofile.current_test_bytes(nprofile_before) == current
    resolution_before = resolution.historical_bytes(path, current)
    assert resolution.current_test_bytes(resolution_before) == current
    account_before = account.historical_bytes(path, current)
    assert account.current_test_bytes(account_before) == current
    canary_before = canary.historical_bytes(path, current)
    assert canary.current_test_bytes(canary_before) == current
    isolated_before = isolated.historical_bytes(path, current)
    assert isolated.current_test_bytes(isolated_before) == current
    portable_before = portable.historical_bytes(path, current)
    assert portable.current_test_bytes(portable_before) == current
    proof_before = proof.historical_bytes(path, current)
    assert proof.current_test_bytes(proof_before) == current
    recheck_before = recheck.historical_bytes(path, current)
    assert recheck.current_test_bytes(recheck_before) == current
    verifier_before = verifier.historical_bytes(path, current)
    assert verifier.current_test_bytes(verifier_before) == current
    linux_before = linux.historical_bytes(path, current)
    assert linux.current_test_bytes(linux_before) == current
    performance_before = performance.historical_bytes(path, current)
    assert performance.current_test_bytes(performance_before) == current
    runner_before = runner.historical_bytes(path, current)
    assert runner.current_test_bytes(runner_before) == current
    roadmap_before = roadmap.historical_bytes(path, current)
    assert roadmap.current_test_bytes(roadmap_before) == current
    with pytest.raises(ValueError, match="unreviewed current source"):
        profile.historical_bytes(path, current + b" ")


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "smx_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = profile.historical_bytes(path, raw) if route in ("current_test", "old_bytes") else None
    current_packets = packets() if route == "catalog" else None
    layer = layer_packets() if route == "payloads" else None
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
    old_smx = smx.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "smx_old" else None
    old_phr = phr.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "phr_old" else None
    old_sv4 = sv4.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "sv4_old" else None
    old_hs43 = hs43.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "hs43_old" else None
    old_rav3 = rav3.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "rav3_old" else None
    old_deadlines = deadlines.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "deadlines_old" else None
    old_events = events.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "events_old" else None
    old_filters = filters.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "filters_old" else None
    old_loop = loop.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "loop_old" else None
    old_manifest = manifest.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "manifest_old" else None
    old_ledger = ledger.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "ledger_old" else None
    old_adoption = adoption.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "adoption_old" else None
    old_amendment = amendment.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "amendment_old" else None
    old_bprofile = bprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "bprofile_old" else None
    old_mprofile = mprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "mprofile_old" else None
    old_eprofile = eprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "eprofile_old" else None
    old_lprofile = lprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "lprofile_old" else None
    old_fprofile = fprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "fprofile_old" else None
    old_oprofile = oprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "oprofile_old" else None
    old_uprofile = uprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "uprofile_old" else None
    old_jprofile = jprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "jprofile_old" else None
    old_kprofile = kprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "kprofile_old" else None
    old_tprofile = tprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "tprofile_old" else None
    old_zprofile = zprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "zprofile_old" else None
    old_yprofile = yprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "yprofile_old" else None
    old_xprofile = xprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "xprofile_old" else None
    old_pprofile = pprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "pprofile_old" else None
    old_aprofile = aprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "aprofile_old" else None
    old_vprofile = vprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "vprofile_old" else None
    old_cprofile = cprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "cprofile_old" else None
    old_qprofile = qprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "qprofile_old" else None
    old_hprofile = hprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "hprofile_old" else None
    old_dprofile = dprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "dprofile_old" else None
    old_sprofile = sprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "sprofile_old" else None
    old_wprofile = wprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "wprofile_old" else None
    old_rprofile = rprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "rprofile_old" else None
    old_gprofile = gprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "gprofile_old" else None
    old_iprofile = iprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "iprofile_old" else None
    old_nprofile = nprofile.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "nprofile_old" else None
    old_resolution = resolution.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "resolution_old" else None
    old_account = account.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "account_old" else None
    old_canary = canary.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "canary_old" else None
    old_isolated = isolated.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "isolated_old" else None
    old_portable = portable.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "portable_old" else None
    old_proof = proof.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "proof_old" else None
    old_recheck = recheck.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "recheck_old" else None
    old_verifier = verifier.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "verifier_old" else None
    old_linux = linux.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "linux_old" else None
    old_performance = performance.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "performance_old" else None
    old_runner = runner.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "runner_old" else None
    old_roadmap = roadmap.historical_bytes(roadmap.MASTER_PATH, roadmap.regular_bytes(roadmap.MASTER_PATH)) if route == "roadmap_old" else None
    calls = {
        "authority": profile.authority,
        "changed": lambda: profile.historical_bytes(path, raw),
        "old_bytes": lambda: profile.historical_bytes(path, before),
        "unchanged": lambda: profile.historical_bytes("architecture/repositories.yaml", b"unrelated"),
        "historical_test": lambda: profile.historical_test_bytes(raw),
        "current_test": lambda: profile.current_test_bytes(before),
        "catalog": lambda: profile.historical_catalog(current_packets),
        "payloads": lambda: profile.validate_packet_payloads(layer),
        "smx_old": lambda: smx.historical_bytes(roadmap.MASTER_PATH, old_smx),
        "phr_old": lambda: phr.historical_bytes(roadmap.MASTER_PATH, old_phr),
        "sv4_old": lambda: sv4.historical_bytes(roadmap.MASTER_PATH, old_sv4),
        "hs43_old": lambda: hs43.historical_bytes(roadmap.MASTER_PATH, old_hs43),
        "rav3_old": lambda: rav3.historical_bytes(roadmap.MASTER_PATH, old_rav3),
        "deadlines_old": lambda: deadlines.historical_bytes(roadmap.MASTER_PATH, old_deadlines),
        "events_old": lambda: events.historical_bytes(roadmap.MASTER_PATH, old_events),
        "filters_old": lambda: filters.historical_bytes(roadmap.MASTER_PATH, old_filters),
        "loop_old": lambda: loop.historical_bytes(roadmap.MASTER_PATH, old_loop),
        "manifest_old": lambda: manifest.historical_bytes(roadmap.MASTER_PATH, old_manifest),
        "ledger_old": lambda: ledger.historical_bytes(roadmap.MASTER_PATH, old_ledger),
        "adoption_old": lambda: adoption.historical_bytes(roadmap.MASTER_PATH, old_adoption),
        "amendment_old": lambda: amendment.historical_bytes(roadmap.MASTER_PATH, old_amendment),
        "bprofile_old": lambda: bprofile.historical_bytes(roadmap.MASTER_PATH, old_bprofile),
        "mprofile_old": lambda: mprofile.historical_bytes(roadmap.MASTER_PATH, old_mprofile),
        "eprofile_old": lambda: eprofile.historical_bytes(roadmap.MASTER_PATH, old_eprofile),
        "lprofile_old": lambda: lprofile.historical_bytes(roadmap.MASTER_PATH, old_lprofile),
        "fprofile_old": lambda: fprofile.historical_bytes(roadmap.MASTER_PATH, old_fprofile),
        "oprofile_old": lambda: oprofile.historical_bytes(roadmap.MASTER_PATH, old_oprofile),
        "uprofile_old": lambda: uprofile.historical_bytes(roadmap.MASTER_PATH, old_uprofile),
        "jprofile_old": lambda: jprofile.historical_bytes(roadmap.MASTER_PATH, old_jprofile),
        "kprofile_old": lambda: kprofile.historical_bytes(roadmap.MASTER_PATH, old_kprofile),
        "tprofile_old": lambda: tprofile.historical_bytes(roadmap.MASTER_PATH, old_tprofile),
        "zprofile_old": lambda: zprofile.historical_bytes(roadmap.MASTER_PATH, old_zprofile),
        "yprofile_old": lambda: yprofile.historical_bytes(roadmap.MASTER_PATH, old_yprofile),
        "xprofile_old": lambda: xprofile.historical_bytes(roadmap.MASTER_PATH, old_xprofile),
        "pprofile_old": lambda: pprofile.historical_bytes(roadmap.MASTER_PATH, old_pprofile),
        "aprofile_old": lambda: aprofile.historical_bytes(roadmap.MASTER_PATH, old_aprofile),
        "vprofile_old": lambda: vprofile.historical_bytes(roadmap.MASTER_PATH, old_vprofile),
        "cprofile_old": lambda: cprofile.historical_bytes(roadmap.MASTER_PATH, old_cprofile),
        "qprofile_old": lambda: qprofile.historical_bytes(roadmap.MASTER_PATH, old_qprofile),
        "hprofile_old": lambda: hprofile.historical_bytes(roadmap.MASTER_PATH, old_hprofile),
        "dprofile_old": lambda: dprofile.historical_bytes(roadmap.MASTER_PATH, old_dprofile),
        "sprofile_old": lambda: sprofile.historical_bytes(roadmap.MASTER_PATH, old_sprofile),
        "wprofile_old": lambda: wprofile.historical_bytes(roadmap.MASTER_PATH, old_wprofile),
        "rprofile_old": lambda: rprofile.historical_bytes(roadmap.MASTER_PATH, old_rprofile),
        "gprofile_old": lambda: gprofile.historical_bytes(roadmap.MASTER_PATH, old_gprofile),
        "iprofile_old": lambda: iprofile.historical_bytes(roadmap.MASTER_PATH, old_iprofile),
        "nprofile_old": lambda: nprofile.historical_bytes(roadmap.MASTER_PATH, old_nprofile),
        "resolution_old": lambda: resolution.historical_bytes(roadmap.MASTER_PATH, old_resolution),
        "account_old": lambda: account.historical_bytes(roadmap.MASTER_PATH, old_account),
        "canary_old": lambda: canary.historical_bytes(roadmap.MASTER_PATH, old_canary),
        "isolated_old": lambda: isolated.historical_bytes(roadmap.MASTER_PATH, old_isolated),
        "portable_old": lambda: portable.historical_bytes(roadmap.MASTER_PATH, old_portable),
        "proof_old": lambda: proof.historical_bytes(roadmap.MASTER_PATH, old_proof),
        "recheck_old": lambda: recheck.historical_bytes(roadmap.MASTER_PATH, old_recheck),
        "verifier_old": lambda: verifier.historical_bytes(roadmap.MASTER_PATH, old_verifier),
        "linux_old": lambda: linux.historical_bytes(roadmap.MASTER_PATH, old_linux),
        "performance_old": lambda: performance.historical_bytes(roadmap.MASTER_PATH, old_performance),
        "runner_old": lambda: runner.historical_bytes(roadmap.MASTER_PATH, old_runner),
        "roadmap_old": lambda: roadmap.historical_bytes(roadmap.MASTER_PATH, old_roadmap),
    }
    calls[route]()
    original = profile.regular_bytes

    def changed_reader(relative):
        value = original(relative)
        return value + b" " if relative == profile.AUTHORITY_PATH else value

    monkeypatch.setattr(profile, "regular_bytes", changed_reader)
    with pytest.raises(ValueError, match="compiled filter programs v2 history authority digest"):
        calls[route]()


def test_catalog_uses_only_pinned_parsed_data_and_checks_each_input_again(monkeypatch):
    current = layer_packets()
    profile._packet_rules()

    def unexpected_yaml(_raw):
        pytest.fail("catalog projection must not reparse every predecessor YAML")

    monkeypatch.setattr(profile, "safe_load", unexpected_yaml)
    assert profile.validate_packet_payloads(current) is None
    current["MET-001"]["objective"] += " changed after a successful call"
    with pytest.raises(ValueError, match="changed packet payload"):
        profile.validate_packet_payloads(current)


def test_historical_catalog_reuses_frozen_packet_pins_but_rechecks_authority(monkeypatch):
    current = packets()

    def unexpected(*_args, **_kwargs):
        pytest.fail("historical traversal must not reparse authority or packet YAML")

    monkeypatch.setattr(profile, "authority", unexpected)
    monkeypatch.setattr(profile, "safe_load", unexpected)
    assert len(profile.historical_catalog(current)) == 239


def test_historical_catalog_does_not_initialize_predecessor_packet_rules(monkeypatch):
    current = packets()
    profile._packet_rules_for.cache_clear()
    original = profile.regular_bytes
    packet_reads = []

    def counted(path):
        if path.startswith("task-packets/"):
            packet_reads.append(path)
        return original(path)

    monkeypatch.setattr(profile, "regular_bytes", counted)
    assert len(profile.historical_catalog(current)) == 239
    assert packet_reads == ["task-packets/" + profile.NEW_PACKET + ".yaml"]
    assert profile._packet_rules_for.cache_info().currsize == 0


def test_full_packet_expectations_initialize_once_and_remain_immutable(monkeypatch):
    profile._packet_rules_for.cache_clear()
    original = profile.safe_load
    parsed = []

    def counted(raw):
        parsed.append(raw)
        return original(raw)

    monkeypatch.setattr(profile, "safe_load", counted)
    rules = profile._packet_rules()
    assert len(rules) == 240 and len(parsed) == 239
    assert profile._packet_rules() is rules and len(parsed) == 239
    with pytest.raises(TypeError):
        rules["MET-001"] = ("0" * 64, "0" * 64)


def test_first_full_packet_check_refuses_changed_old_yaml(monkeypatch):
    current = layer_packets()
    profile._packet_rules_for.cache_clear()
    original = profile.regular_bytes

    def changed_reader(path):
        raw = original(path)
        return raw + b" " if path == "task-packets/MET-001.yaml" else raw

    monkeypatch.setattr(profile, "regular_bytes", changed_reader)
    with pytest.raises(ValueError, match="packet YAML drift: MET-001"):
        profile.validate_packet_payloads(current)
    assert profile._packet_rules_for.cache_info().currsize == 0


def test_cached_expected_rules_do_not_cache_payload_or_authority_verdict(monkeypatch):
    current = layer_packets()
    profile.validate_packet_payloads(current)
    current["MET-001"]["objective"] += " unreviewed"
    with pytest.raises(ValueError, match="changed packet payload: MET-001"):
        profile.validate_packet_payloads(current)
    original = profile.regular_bytes

    def changed_reader(path):
        raw = original(path)
        return raw + b" " if path == profile.AUTHORITY_PATH else raw

    monkeypatch.setattr(profile, "regular_bytes", changed_reader)
    with pytest.raises(ValueError, match="compiled filter programs v2 history authority digest"):
        profile.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = layer_packets()
    profile.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "compiled-filter-programs-v2-authority.json").write_bytes(
        profile.regular_bytes(profile.AUTHORITY_PATH))
    (tmp_path / "task-packets").mkdir()
    monkeypatch.setattr(profile, "ROOT", tmp_path)
    with pytest.raises(FileNotFoundError):
        profile.validate_packet_payloads(current)


@pytest.mark.parametrize("fault", ["opaque", "cycle", "changed"])
def test_historical_traversal_leaves_predecessor_refusal_to_its_owner(fault):
    current = packets()
    if fault == "opaque":
        current["MET-001"] = object()
    elif fault == "cycle":
        cycle = {}
        cycle["self"] = cycle
        current["MET-001"] = cycle
    else:
        current["MET-001"]["objective"] += " changed"
    previous = profile.historical_catalog(current)
    assert previous["MET-001"] is current["MET-001"]
    with pytest.raises(ValueError, match="changed packet payload"):
        profile.validate_packet_payloads(profile.successor.historical_catalog(current))


@pytest.mark.parametrize("fault", ["payload", "yaml"])
def test_historical_traversal_freshly_checks_its_own_packet(monkeypatch, fault):
    current = packets()
    if fault == "payload":
        current[profile.NEW_PACKET]["objective"] += " changed"
    else:
        original = profile.regular_bytes

        def changed_reader(path):
            raw = original(path)
            return raw + b" " if path == "task-packets/" + profile.NEW_PACKET + ".yaml" else raw

        monkeypatch.setattr(profile, "regular_bytes", changed_reader)
    with pytest.raises(ValueError):
        profile.historical_catalog(current)


def test_validator_checks_current_disk_packet_bytes_after_parsing(monkeypatch):
    original = profile.regular_bytes

    def changed_reader(path):
        raw = original(path)
        return raw + b" " if path == "task-packets/MET-001.yaml" else raw

    monkeypatch.setattr(profile, "regular_bytes", changed_reader)
    with pytest.raises(ValueError, match="packet YAML drift"):
        profile.validate()


@pytest.mark.parametrize("mutation", ["append", "duplicate_literal"])
def test_normalized_validator_pin_rejects_source_mutation(monkeypatch, mutation):
    original = profile.regular_bytes

    def changed_reader(path):
        raw = original(path)
        if path == profile.VALIDATOR_PATH:
            raw += (b"\n# unreviewed\n" if mutation == "append" else
                    b'\nAUTHORITY_SHA256 = "' + profile.AUTHORITY_SHA256.encode() + b'"\n')
        return raw

    monkeypatch.setattr(profile, "regular_bytes", changed_reader)
    # The newer MET-PERF-040 layer refuses a mutated validator before this layer.
    with pytest.raises(ValueError, match="unreviewed current source: scripts/validate_compiled_filter_programs_v2.py"):
        profile.validate()


@pytest.mark.parametrize("fault", ["duplicate", "boolean", "negative", "out_of_bounds", "encoding", "empty", "overlap"])
def test_inverse_parser_refuses_ambiguous_or_unbounded_hunks(monkeypatch, fault):
    record = deepcopy(profile.authority())
    path = next(iter(record["changedFiles"]))
    hunks = record["changedFiles"][path]["reverseHunks"]
    if fault == "duplicate":
        hunks.insert(0, deepcopy(hunks[0]))
    elif fault == "boolean":
        hunks[0]["at"] = True
    elif fault == "negative":
        hunks[0]["at"] = -1
    elif fault == "out_of_bounds":
        hunks[0]["at"] = profile.MAX_FILE_BYTES + 1
    elif fault == "encoding":
        hunks[0]["insertBase64"] += "!"
    elif fault == "empty":
        hunks[0]["insertBase64"] = hunks[0]["removeBase64"]
    else:
        hunks[:] = [{"at": 0, "removeBase64": "YWJj", "insertBase64": "eA=="},
                    {"at": 1, "removeBase64": "Yg==", "insertBase64": "eQ=="}]
    monkeypatch.setattr(profile, "authority", lambda: record)
    with pytest.raises(ValueError):
        profile._rules()


def test_inverse_rules_and_packet_expectations_are_immutable():
    path = next(iter(profile._PROJECTION_RULES))
    with pytest.raises(TypeError):
        profile._PROJECTION_RULES[path] = {}
    with pytest.raises(TypeError):
        profile._PROJECTION_RULES[path]["afterSha256"] = "0" * 64
    with pytest.raises(TypeError):
        profile._PACKET_BYTE_RULES["MET-001"] = "0" * 64
    with pytest.raises(TypeError):
        profile._packet_rules()["MET-001"] = ("0" * 64, "0" * 64)
    raw = profile.regular_bytes(path)
    with pytest.raises(ValueError, match="inverse hunk current bytes"):
        profile._inverse(raw, ((0, b"not-current", b"old"),))
    with pytest.raises(ValueError, match="inverse hunk bounds"):
        profile._inverse(raw, ((len(raw) + 1, b"", b"old"),))


def test_ambiguous_test_projections_are_refused(monkeypatch):
    path = changed_test()
    current = profile.regular_bytes(path)
    before = profile.historical_bytes(path, current)
    rules = dict(profile._PROJECTION_RULES)
    rules["tests/ambiguous_unreviewed.py"] = rules[path]
    monkeypatch.setattr(profile, "_PROJECTION_RULES", MappingProxyType(rules))
    with pytest.raises(ValueError, match="ambiguous current test"):
        profile.historical_test_bytes(current)
    with pytest.raises(ValueError, match="ambiguous predecessor test"):
        profile.current_test_bytes(before)


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'])
def test_authority_parser_rejects_duplicate_and_nonfinite_data(raw):
    with pytest.raises(ValueError):
        profile.parse(raw)


@pytest.mark.parametrize("route", [profile.historical_test_bytes, profile.current_test_bytes])
def test_mutable_test_input_is_refused(route):
    with pytest.raises(ValueError, match="test bytes required"):
        route(bytearray(b"mutable"))


@pytest.mark.parametrize("path", ["/absolute", "../outside", "a/../b", "a//b", "a\\b", "a\nb"])
def test_untrusted_source_paths_are_refused(path):
    with pytest.raises(ValueError, match="relative source path"):
        profile.historical_bytes(path, b"input")


def test_unlinked_bounded_source_reads(tmp_path, monkeypatch):
    monkeypatch.setattr(profile, "ROOT", tmp_path)
    original = tmp_path / "plain"
    original.write_bytes(b"source")
    assert profile.regular_bytes("plain") == b"source"
    (tmp_path / "alias").symlink_to(original)
    with pytest.raises(ValueError, match="bounded regular source file"):
        profile.regular_bytes("alias")
    os.link(original, tmp_path / "hardlink")
    with pytest.raises(ValueError, match="bounded regular source file"):
        profile.regular_bytes("plain")
    (tmp_path / "outside").mkdir()
    (tmp_path / "ancestor").symlink_to(tmp_path / "outside", target_is_directory=True)
    with pytest.raises(ValueError, match="linked source ancestor"):
        profile.regular_bytes("ancestor/file")


def test_source_read_detects_concurrent_change(tmp_path, monkeypatch):
    monkeypatch.setattr(profile, "ROOT", tmp_path)
    target = tmp_path / "plain"
    target.write_bytes(b"source")
    original = Path.read_bytes

    def racing_read(path):
        raw = original(path)
        if path == target:
            target.write_bytes(b"changed and longer")
        return raw

    monkeypatch.setattr(Path, "read_bytes", racing_read)
    with pytest.raises(ValueError, match="source changed during read"):
        profile.regular_bytes("plain")


def test_changed_historical_tests_retain_their_test_identities():
    def identities(raw):
        names = []

        def visit(nodes, prefix=""):
            for node in nodes:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                    names.append(prefix + node.name)
                elif isinstance(node, ast.ClassDef):
                    visit(node.body, prefix + node.name + ".")

        visit(ast.parse(raw).body)
        assert len(names) == len(set(names))
        return set(names)

    for path in profile._PROJECTION_RULES:
        if path.startswith("tests/") and path.endswith(".py"):
            current = profile.regular_bytes(path)
            before = profile.historical_bytes(path, current)
            assert identities(before) <= identities(current), path


def test_new_projection_has_no_predecessor_validator_import():
    tree = ast.parse(profile.regular_bytes(profile.VALIDATOR_PATH))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert "validate_" not in (node.module or "")
        elif isinstance(node, ast.Import):
            # Only the newer successor layer may be imported, never a predecessor.
            assert all("validate_" not in alias.name or alias.name == "validate_chain_depth_headroom"
                       for alias in node.names)


def _count_authority_reads(monkeypatch):
    counts = {}
    for module in (profile.successor, profile, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner):
        original = module.regular_bytes

        def counted(relative, _module=module, _original=original):
            if relative == _module.AUTHORITY_PATH:
                counts[_module.__name__] = counts.get(_module.__name__, 0) + 1
            return _original(relative)

        monkeypatch.setattr(module, "regular_bytes", counted)
    return counts


@pytest.mark.parametrize("route", ["changed", "old_bytes", "unchanged", "historical_test", "current_test"])
def test_every_newer_authority_is_read_exactly_once_per_route(monkeypatch, route):
    """Linear rechecks: one fresh complete read of each authority per public call."""
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = runner.historical_bytes(path, raw)
    counts = _count_authority_reads(monkeypatch)
    calls = {
        "changed": lambda: runner.historical_bytes(path, raw),
        "old_bytes": lambda: runner.historical_bytes(path, before),
        "unchanged": lambda: runner.historical_bytes("architecture/repositories.yaml", b"unrelated"),
        "historical_test": lambda: runner.historical_test_bytes(raw),
        "current_test": lambda: runner.current_test_bytes(before),
    }
    calls[route]()
    expected = {module.__name__: 1 for module in (profile.successor, profile, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner)}
    if route == "current_test":
        # The forward route reads this layer's newest bytes and then projects them forward once more.
        assert all(counts[name] >= 1 for name in expected) and set(counts) == set(expected)
    else:
        assert counts == expected


def _rebind(monkeypatch, served, reviewed=True):
    """Serve changed bytes for some paths and re-pin their digests (and, unless reviewed is False, their reviewed-subject
    digests), so the checks behind the digest binding are exercised."""
    original = profile.reviewed_bytes
    pins = dict(profile.ERA_SHA256)
    subject = dict(profile.REVIEWED_SHA256)
    for path, raw in served.items():
        if path in pins:
            pins[path] = profile.digest(raw)
        if reviewed and path in subject:
            subject[path] = profile.digest(raw)
    monkeypatch.setattr(profile, "ERA_SHA256", MappingProxyType(pins))
    monkeypatch.setattr(profile, "REVIEWED_SHA256", subject)
    monkeypatch.setattr(profile, "reviewed_bytes", lambda target: served[target] if target in served else original(target))


def _dump(value):
    return (json.dumps(value, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def _json(path):
    return json.loads(profile.reviewed_bytes(path))


def _flip(raw, at=-1):
    at = at % len(raw)
    return raw[:at] + bytes([raw[at] ^ 1]) + raw[at + 1:]


GATE_X86 = profile.PROGRAMS_DIR + "EFFECT_GATE.x86_64.bpf"
OLD_BROKER = profile.PREDECESSOR_DIR + "programs/BROKER.x86_64.bpf"
OLD_GATE = profile.PREDECESSOR_DIR + "programs/EFFECT_GATE.x86_64.bpf"
VECTORS = profile.V4_DIR + "vectors.json"


def test_the_contract_holds_for_this_era():
    assert profile.validate_compiled_filter_programs_v2() is None


def test_every_contract_file_and_input_is_pinned():
    pinned = set(profile.ERA_SHA256)
    assert set(profile.NEW_FILES) <= pinned and len(pinned) == 34
    assert {*profile.V4_SOURCES, profile.V4_STATUS, profile.PREDECESSOR_INDEX, profile.V2_EDGE, profile.HS43_RECORD,
            profile.REPOSITORIES, profile.SAFE_YAML} <= pinned
    assert {profile.PREDECESSOR_DIR + "programs/%s.%s.bpf" % (role, arch)
            for role in profile.ROLES for arch in profile.ARCHES} <= pinned
    assert set(profile.REVIEWED_SHA256) == set(profile.CONTRACT_FILES) - {profile.STATUS_PATH}
    for path, expected in profile.ERA_SHA256.items():
        assert profile.digest(profile.regular_bytes(path)) == expected


@pytest.mark.parametrize("path", sorted(profile.ERA_SHA256))
def test_every_era_file_is_bound_by_digest_before_anything_runs(monkeypatch, path):
    original = profile.reviewed_bytes
    executed = []
    monkeypatch.setattr(profile, "reviewed_bytes", lambda target: original(target) + b" " if target == path else original(target))
    monkeypatch.setattr(profile, "_era_model", lambda *args: executed.append(args[0]))
    with pytest.raises(ValueError, match=re.escape("unreviewed compiled filter programs v2 source: " + path)):
        profile.validate_compiled_filter_programs_v2()
    assert executed == []


def test_a_path_outside_the_era_is_refused_before_it_is_read():
    with pytest.raises(ValueError, match="MET-ENFORCE-029 reviewed bytes are bound: README.md"):
        profile._verified("README.md")


@pytest.mark.parametrize("path", profile.FROZEN_PATHS)
def test_the_frozen_predecessors_may_not_be_changed_by_this_packet(monkeypatch, path):
    rules = dict(profile._PROJECTION_RULES)
    rules[path] = {"beforeSha256": "0" * 64, "afterSha256": "0" * 64}
    monkeypatch.setattr(profile, "_PROJECTION_RULES", MappingProxyType(rules))
    with pytest.raises(ValueError, match="stay byte-identical"):
        profile.validate_compiled_filter_programs_v2()


@pytest.mark.parametrize("path", ["architecture/compiled-filter-programs/programs/EFFECT_GATE.x86_64.v4.bpf",
                                  "architecture/seccomp-allowlists-v4/vectors-v2.json",
                                  "architecture/seccomp-allowlists-v3/note.md", "architecture/w03-plan-v2/amendment.json",
                                  "architecture/artifact-edges/README-v2.md"])
def test_no_file_may_be_added_to_a_frozen_predecessor(monkeypatch, path):
    record = copy.deepcopy(profile.authority())
    record["newFiles"][path] = "0" * 64
    monkeypatch.setattr(profile, "authority", lambda: record)
    with pytest.raises(ValueError, match="stay byte-identical"):
        profile.validate_compiled_filter_programs_v2()


@pytest.mark.parametrize("change", ["missing", "edge_v4", "contract_extra"])
def test_the_contract_files_are_new_in_this_packet_each_once(monkeypatch, change):
    record = copy.deepcopy(profile.authority())
    if change == "missing":
        del record["newFiles"][profile.V3_README]
    elif change == "edge_v4":
        record["newFiles"][profile.EDGES_DIR + "operator-harness-engineering-v4.json"] = "0" * 64
    else:
        record["newFiles"][profile.CONTRACT_DIR + "review-round2.json"] = "0" * 64
    monkeypatch.setattr(profile, "authority", lambda: record)
    with pytest.raises(ValueError, match="the contract's ten files are new in this packet, each once"):
        profile.validate_compiled_filter_programs_v2()


def _tree_copy(tmp_path):
    """The contract's ten files under tmp_path, as git checks out mode 100644."""
    for path in profile.NEW_FILES:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(profile.regular_bytes(path))
        target.chmod(0o644)
    return tmp_path


def _serve_tree(monkeypatch, root):
    """Read the listing and modes of root with the layer's own readers, then serve them as this packet's tree."""
    real_root = profile.ROOT
    monkeypatch.setattr(profile, "ROOT", root)
    tree = profile.reviewed_tree(profile.CONTRACT_DIR)
    modes = {}
    for path in (profile.CONTRACT_DIR[:-1], *profile.NEW_FILES):
        if os.path.lexists(root / path):
            modes[path] = profile.reviewed_mode(path)
    monkeypatch.setattr(profile, "ROOT", real_root)
    monkeypatch.setattr(profile, "reviewed_tree", lambda directory: dict(tree))
    monkeypatch.setattr(profile, "reviewed_mode", lambda path: modes[path])


def test_the_contract_tree_is_read_from_the_checkout(tmp_path, monkeypatch):
    _serve_tree(monkeypatch, _tree_copy(tmp_path))
    assert profile.validate_compiled_filter_programs_v2() is None


@pytest.mark.parametrize("change, message", [
    ("program_symlink", "a contract file is a regular file of git mode 100644: " + GATE_X86),
    ("program_executable", "a contract file is a regular file of git mode 100644: " + GATE_X86),
    ("edge_executable", "a contract file is a regular file of git mode 100644: " + "architecture/artifact-edges/operator-harness-engineering-v3.json"),
    ("publisher_symlink", "a contract file is a regular file of git mode 100644: scripts/compiled_filter_programs_v2.py"),
    ("thirteenth_program", "the contract directory holds exactly its seven files and programs/"),
    ("extra_file", "the contract directory holds exactly its seven files and programs/"),
    ("missing_file", "the contract directory holds exactly its seven files and programs/"),
    ("linked_programs", "the contract directory holds exactly its seven files and programs/"),
    ("linked_directory", "the contract directory is a directory, not a link"),
])
def test_the_contract_tree_is_closed_and_every_file_is_mode_100644(tmp_path, monkeypatch, change, message):
    root = _tree_copy(tmp_path / "tree")
    contract = root / profile.CONTRACT_DIR
    outside = tmp_path / "outside"
    outside.mkdir()
    if change == "program_symlink":
        (outside / "program").write_bytes((root / GATE_X86).read_bytes())
        (root / GATE_X86).unlink()
        (root / GATE_X86).symlink_to(outside / "program")
    elif change == "program_executable":
        (root / GATE_X86).chmod(0o755)
    elif change == "edge_executable":
        (root / profile.V3_EDGE).chmod(0o744)
    elif change == "publisher_symlink":
        (outside / "publisher.py").write_bytes((root / profile.PUBLISHER).read_bytes())
        (root / profile.PUBLISHER).unlink()
        (root / profile.PUBLISHER).symlink_to(outside / "publisher.py")
    elif change == "thirteenth_program":
        (contract / "programs/BROKER.x86_64.bpf").write_bytes(profile.regular_bytes(OLD_BROKER))
    elif change == "extra_file":
        (contract / ".notes").write_bytes(b"x")
    elif change == "missing_file":
        (contract / "REVIEW_BRIEF.md").unlink()
    elif change == "linked_programs":
        (contract / "programs").rename(outside / "programs")
        (contract / "programs").symlink_to(outside / "programs", target_is_directory=True)
    else:
        contract.rename(outside / "contract")
        (root / profile.CONTRACT_DIR[:-1]).symlink_to(outside / "contract", target_is_directory=True)
    _serve_tree(monkeypatch, root)
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.validate_compiled_filter_programs_v2()


def test_the_tree_readers_report_links_and_modes(tmp_path, monkeypatch):
    root = _tree_copy(tmp_path)
    (root / profile.CONTRACT_DIR / "link").symlink_to(root / GATE_X86)
    monkeypatch.setattr(profile, "ROOT", root)
    tree = profile.reviewed_tree(profile.CONTRACT_DIR)
    assert set(tree) == profile.CONTRACT_TREE | {profile.CONTRACT_DIR + "link"}
    assert stat.S_ISLNK(tree[profile.CONTRACT_DIR + "link"]) and stat.S_ISDIR(tree[profile.PROGRAMS_DIR[:-1]])
    assert stat.S_IMODE(profile.reviewed_mode(GATE_X86)) == 0o644
    with pytest.raises(ValueError, match="relative source path"):
        profile.reviewed_mode("../outside")


@pytest.mark.parametrize("change, message", [
    ("state", "adopted MET-ENFORCE-029 status"),
    ("packet", "adopted MET-ENFORCE-029 status"),
    ("schema", "adopted MET-ENFORCE-029 status"),
    ("base", "adopted MET-ENFORCE-029 status"),
    ("source", "adopted MET-ENFORCE-029 status"),
    ("predecessor", "adopted MET-ENFORCE-029 status"),
    ("contract_files", "adopted MET-ENFORCE-029 status"),
    ("kept", "adopted MET-ENFORCE-029 status"),
    ("extra", "adopted MET-ENFORCE-029 status"),
    ("key_order", "adopted MET-ENFORCE-029 status"),
    ("carried", "adopted MET-ENFORCE-029 status"),
    ("readme_note", "adopted MET-ENFORCE-029 status"),
    ("r10_packet", "adopted MET-ENFORCE-029 status"),
    ("independence", "adopted MET-ENFORCE-029 status"),
    ("decision_text", "the owner's decisions, verbatim"),
    ("decision_hs43", "the owner's decisions, verbatim"),
    ("decision_order", "the owner's decisions, verbatim"),
    ("decision_date", "the owner's decisions, verbatim"),
    ("discharge", "allowlists v4's open republication item is discharged in this record only"),
    ("round_verdict", "review round 1 is bound to its record and subject"),
    ("round_subject", "review round 1 is bound to its record and subject"),
    ("round_record", "review round 1 is bound to its record and subject"),
    ("round_findings", "review round 1 is bound to its record and subject"),
    ("second_round", "review round 1 is bound to its record and subject"),
])
def test_a_status_field_change_is_refused(monkeypatch, change, message):
    status = _json(profile.STATUS_PATH)
    if change == "state":
        status["contractState"] = "CANDIDATE"
    elif change == "packet":
        status["packet"] = "MET-ENFORCE-028"
    elif change == "schema":
        status["schemaVersion"] = "planeon.internal.met-enforce-028-status/v1"
    elif change == "base":
        status["base"] = profile.BASE_COMMIT
    elif change == "source":
        status["source"]["commit"] = "0" * 40
    elif change == "predecessor":
        status["predecessor"]["packet"] = "MET-ENFORCE-024"
    elif change == "contract_files":
        status["contractFiles"].append(profile.REVIEW_RECORD)
    elif change == "kept":
        status["keptCopies"] = [profile.README_PATH]
    elif change == "extra":
        status["implementationReady"] = True
    elif change == "key_order":
        status = {"packet": status.pop("packet"), **status}
    elif change == "carried":
        status["carriedNotes"].pop("R1-7")
    elif change == "readme_note":
        status["readmeStatusNote"] = "README.md keeps its status line"
    elif change == "r10_packet":
        status["carriedToR10"]["packet"] = "HE-003A"
    elif change == "independence":
        status["reviewerIndependence"] = "AUTHOR"
    elif change == "decision_text":
        status["ownerDecisions"][3]["decision"] = status["ownerDecisions"][3]["decision"].replace("- no riders;\n", "")
    elif change == "decision_hs43":
        status["ownerDecisions"][0]["decision"] = "(b) readlink exe for the I07 writer"
    elif change == "decision_order":
        status["ownerDecisions"].reverse()
    elif change == "decision_date":
        status["ownerDecisions"][2]["date"] = "2026-10-14"
    elif change == "discharge":
        status["discharges"]["openObligation"] = "the compiled filter programs are republished from v4"
    elif change == "round_verdict":
        status["reviewRounds"][0]["verdict"] = "CHANGES_REQUIRED"
    elif change == "round_subject":
        status["reviewRounds"][0]["subject"]["tree"] = "0" * 40
    elif change == "round_record":
        status["reviewRounds"][0]["recordSha256"] = "sha256:" + "0" * 64
    elif change == "round_findings":
        status["reviewRounds"][0]["findings"].pop()
    else:
        status["reviewRounds"].append(dict(status["reviewRounds"][0], round=2))
    _rebind(monkeypatch, {profile.STATUS_PATH: _dump(status)})
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.validate_compiled_filter_programs_v2()


@pytest.mark.parametrize("change", ["severity", "verdict", "subject", "actions", "finding_added"])
def test_the_review_record_passes_this_subject_with_notes_only(monkeypatch, change):
    record = _json(profile.REVIEW_RECORD)
    if change == "severity":
        record["findings"][2]["severity"] = "MINOR"
    elif change == "verdict":
        record["verdict"] = "CHANGES_REQUIRED"
    elif change == "subject":
        record["subject"]["commit"] = "0" * 40
    elif change == "actions":
        record["actions"]["personalDataSent"] = True
    else:
        record["findings"].append(dict(record["findings"][0], id="R1-8"))
    raw = _dump(record)
    status = _json(profile.STATUS_PATH)
    status["reviewRounds"][0]["recordSha256"] = "sha256:" + profile.digest(raw)
    _rebind(monkeypatch, {profile.REVIEW_RECORD: raw, profile.STATUS_PATH: _dump(status)})
    with pytest.raises(ValueError, match="the round-1 record passes this subject with notes only"):
        profile.validate_compiled_filter_programs_v2()


@pytest.mark.parametrize("path", sorted({profile.README_PATH, profile.INDEX_PATH, profile.V3_EDGE, profile.PUBLISHER, GATE_X86}))
def test_the_adopted_contract_is_the_reviewed_subject(monkeypatch, path):
    _rebind(monkeypatch, {path: profile.reviewed_bytes(path) + b"\n"}, reviewed=False)
    with pytest.raises(ValueError, match=re.escape("the adopted contract is the reviewed round-1 subject: " + path)):
        profile.validate_compiled_filter_programs_v2()


@pytest.mark.parametrize("path, old, new, message", [
    (profile.README_PATH, b"Status: **SUCCESSOR_CANDIDATE_AWAITING_INDEPENDENT_REVIEW**", b"Status: **ADOPTED**",
     "the README keeps its candidate status line: " + profile.README_PATH),
    (profile.V3_README, b"Status: **SUCCESSOR_CANDIDATE_AWAITING_INDEPENDENT_REVIEW**", b"Status: **ADOPTED**",
     "the README keeps its candidate status line: " + profile.V3_README),
    (profile.V3_README, b"\n## `operator-", b"\nStatus: **ADOPTED**\n\n## `operator-",
     "the README keeps its candidate status line: " + profile.V3_README),
    (profile.README_PATH, b"(MET-ENFORCE-029)\n", b"(MET-ENFORCE-030)\n",
     "the README keeps its candidate status line: " + profile.README_PATH),
    (profile.REVIEW_BRIEF_PATH, b"\n", b"\nMET-ENFORCE-029\n", "MET-ENFORCE-029 is written in exactly the restated contract files"),
    (profile.PUBLISHER, b"MET-ENFORCE-029", b"MET-ENFORCE-030", "MET-ENFORCE-029 is written in exactly the restated contract files"),
])
def test_the_readme_status_lines_and_the_packet_id_are_restated(monkeypatch, path, old, new, message):
    raw = profile.reviewed_bytes(path)
    assert raw.count(old) >= 1
    _rebind(monkeypatch, {path: raw.replace(old, new, 1)})
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.validate_compiled_filter_programs_v2()


def test_the_v4_model_is_executed_from_reviewed_bytes(monkeypatch):
    _rebind(monkeypatch, {profile.V4_MODEL: profile.reviewed_bytes(profile.V4_MODEL) + b"\nraise ValueError('era model executed')\n"})
    with pytest.raises(ValueError, match="era model executed"):
        profile.validate_compiled_filter_programs_v2()


def test_the_current_model_is_not_used(monkeypatch):
    from scripts import seccomp_allowlists_v4 as current

    def broken(*_args, **_kwargs):
        raise AssertionError("current module used")

    for name in ("compile_filter", "program_bytes", "run_filter", "seccomp_data", "action_name"):
        monkeypatch.setattr(current, name, broken)
    assert profile.validate_compiled_filter_programs_v2() is None


def test_the_model_imports_only_the_standard_library():
    tree = ast.parse(profile.reviewed_bytes(profile.V4_MODEL))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            names.add(node.module)
    assert names <= {"__future__", "hashlib", "struct", "typing"}


def test_a_changed_published_program_byte_is_refused(monkeypatch):
    _rebind(monkeypatch, {GATE_X86: _flip(profile.reviewed_bytes(GATE_X86), 8 * 175 + 4)})
    with pytest.raises(ValueError, match=re.escape("the pinned v4 model compiles exactly the published program: " + GATE_X86)):
        profile.validate_compiled_filter_programs_v2()


def _rebind_predecessor(monkeypatch, path, raw):
    """Serve a changed MET-ENFORCE-025 program with its index row and pins following it."""
    index = _json(profile.PREDECESSOR_INDEX)
    for row in index["programs"]:
        if profile.PREDECESSOR_DIR + row["path"] == path:
            row["sha256"] = "sha256:" + profile.digest(raw)
    index_raw = _dump(index)
    monkeypatch.setattr(profile, "PREDECESSOR_INDEX_SHA256", profile.digest(index_raw))
    _rebind(monkeypatch, {path: raw, profile.PREDECESSOR_INDEX: index_raw})


@pytest.mark.parametrize("path, message", [
    (OLD_BROKER, "byte-identical to MET-ENFORCE-025's program: " + OLD_BROKER),
    (OLD_GATE, "v3's EFFECT_GATE program with exactly the six-instruction readlinkat block at 173: " + GATE_X86),
])
def test_the_predecessor_programs_are_compared_byte_for_byte(monkeypatch, path, message):
    _rebind_predecessor(monkeypatch, path, _flip(profile.reviewed_bytes(path), 8 * 10 + 4))
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.validate_compiled_filter_programs_v2()


def test_the_predecessor_index_lists_the_seven_roles_on_both_architectures(monkeypatch):
    index = _json(profile.PREDECESSOR_INDEX)
    index["programs"].pop()
    raw = _dump(index)
    monkeypatch.setattr(profile, "PREDECESSOR_INDEX_SHA256", profile.digest(raw))
    _rebind(monkeypatch, {profile.PREDECESSOR_INDEX: raw})
    with pytest.raises(ValueError, match="the seven roles of the v4 policy and MET-ENFORCE-025's fourteen programs"):
        profile.validate_compiled_filter_programs_v2()


def test_the_predecessor_index_must_name_its_programs(monkeypatch):
    _rebind(monkeypatch, {OLD_BROKER: _flip(profile.reviewed_bytes(OLD_BROKER))})
    with pytest.raises(ValueError, match=re.escape("MET-ENFORCE-025's index names its program: " + OLD_BROKER)):
        profile.validate_compiled_filter_programs_v2()


@pytest.mark.parametrize("name, value, message", [
    ("BLOCK_AT", {"aarch64": (34, 78), "x86_64": (174, 267)}, "readlinkat block at 174: " + GATE_X86),
    ("BLOCK_AT", {"aarch64": (34, 79), "x86_64": (173, 267)}, "readlinkat's number on aarch64"),
    ("READLINKAT_BLOCK", ((0x15, 0, 4, None),) + profile.READLINKAT_BLOCK[1:], "readlinkat block at 34: "),
    ("READLINKAT_BLOCK", profile.READLINKAT_BLOCK[:4] + ((0x06, 0, 0, 0x80000000),) * 2, "readlinkat block at 34: "),
    ("V3_GATE_LENGTHS", {"aarch64": 183, "x86_64": 195}, "readlinkat block at 173: " + GATE_X86),
    ("V3_GATE_SHA256", {"aarch64": "0" * 64, "x86_64": "0" * 64}, "readlinkat block at 34: "),
    ("PROGRAM_LENGTHS", {**profile.PROGRAM_LENGTHS, "BROKER": (310, 326)}, "v4's digest and length: BROKER aarch64"),
    ("PROGRAM_SHA256", {**profile.PROGRAM_SHA256, "WORKER": ("0" * 64, profile.PROGRAM_SHA256["WORKER"][1])},
     "v4's digest and length: WORKER aarch64"),
    ("V4_SOURCE_SHA256", {**profile.V4_SOURCE_SHA256, profile.V4_MODEL: "0" * 64}, "the pinned v4 sources and predecessor index"),
    ("PREDECESSOR_INDEX_SHA256", "0" * 64, "the pinned v4 sources and predecessor index"),
    ("GATE_DECISIONS", {"aarch64": 195, "x86_64": 205}, "the replay covers v4's EFFECT_GATE decision vectors"),
    ("GATE_READLINKAT_DECISIONS", {"aarch64": 10, "x86_64": 9}, "the replay covers v4's EFFECT_GATE decision vectors"),
    ("CONSUMER_PACKET", "HE-003A", "adopted MET-ENFORCE-029 status"),
    ("CONSUMER_DIR", "host-enforcement/contracts/seccomp-v3/", "edge record v3 is v2's 31 rows plus exactly"),
    ("V3_ARTIFACT", "w03-transport-effect-gate-contracts-and-compiled-filter-programs", "edge record v3 is v2's 31 rows"),
    ("V2_EDGE_SHA256", "0" * 64, "edge record v2 is the one v3 supersedes"),
    ("Q_PR", profile.Q_PR + " ", "the owner's decisions, verbatim"),
    ("OPEN_ITEM", profile.OPEN_ITEM + ".", "allowlists v4's open republication item"),
    ("REVIEWED_SUBJECT", {**profile.REVIEWED_SUBJECT, "commit": "0" * 40}, "review round 1 is bound to its record and subject"),
    ("CARRIED", ("R1-1", "R1-2", "R1-3", "R1-4", "R1-5", "R1-6", "R1-7"), "adopted MET-ENFORCE-029 status"),
    ("NAMING_FILES", profile.NAMING_FILES - {profile.PUBLISHER}, "MET-ENFORCE-029 is written in exactly"),
])
def test_the_restated_values_bind(monkeypatch, name, value, message):
    monkeypatch.setattr(profile, name, value)
    if name in ("Q_PR",):
        monkeypatch.setattr(profile, "MONITOR_DECISIONS", {**profile.MONITOR_DECISIONS, "Q-PR-1..10": (value, value)})
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.validate_compiled_filter_programs_v2()


def test_the_v4_digests_bind_the_compiled_programs(monkeypatch):
    vectors = _json(VECTORS)
    vectors["filterDigests"]["SERVER"]["x86_64"] = "sha256:" + "0" * 64
    _rebind(monkeypatch, {VECTORS: _dump(vectors)})
    monkeypatch.setattr(profile, "V4_SOURCE_SHA256", {**profile.V4_SOURCE_SHA256, VECTORS: profile.ERA_SHA256[VECTORS]})
    with pytest.raises(ValueError, match="v4's digest and length: SERVER x86_64"):
        profile.validate_compiled_filter_programs_v2()


def _rebind_vectors(monkeypatch, vectors):
    """Serve changed v4 vectors with the index's and the layer's source pins following them."""
    raw = _dump(vectors)
    index = _json(profile.INDEX_PATH)
    index["source"]["files"][VECTORS] = "sha256:" + profile.digest(raw)
    _rebind(monkeypatch, {VECTORS: raw, profile.INDEX_PATH: _dump(index)})
    monkeypatch.setattr(profile, "V4_SOURCE_SHA256", {**profile.V4_SOURCE_SHA256, VECTORS: profile.digest(raw)})


@pytest.mark.parametrize("change, message", [
    ("dropped", "the replay covers v4's EFFECT_GATE decision vectors"),
    ("dropped_readlinkat", "the replay covers v4's EFFECT_GATE decision vectors"),
    ("flipped", "through the published bytes"),
    ("flipped_readlinkat", "through the published bytes"),
])
def test_every_gate_decision_vector_replays(monkeypatch, change, message):
    vectors = _json(VECTORS)
    rows = vectors["decisionChecks"]
    gate = [n for n, row in enumerate(rows) if row["role"] == "EFFECT_GATE"]
    readlinkat = [n for n in gate if rows[n]["nr"] == profile.BLOCK_AT[rows[n]["arch"]][1]]
    if change == "dropped":
        rows.pop(gate[0])
    elif change == "dropped_readlinkat":
        rows.pop(readlinkat[-1])
    else:
        row = rows[gate[3] if change == "flipped" else readlinkat[0]]
        row["expect"] = "KILL_PROCESS" if row["expect"] == "ALLOW" else "ALLOW"
    _rebind_vectors(monkeypatch, vectors)
    with pytest.raises(ValueError, match=message):
        profile.validate_compiled_filter_programs_v2()


@pytest.mark.parametrize("arch, instruction", [("x86_64", 4), ("aarch64", 3), ("x86_64", 0)])
def test_the_replay_runs_through_the_published_bytes(arch, instruction):
    v4, table, vectors, published = profile.validate_programs()
    at = 8 * (profile.BLOCK_AT[arch][0] + instruction)
    changed = dict(published)
    changed[arch] = published[arch][:at + 4] + (0x80000000 if instruction == 4 else 1).to_bytes(4, "little") + published[arch][at + 8:]
    assert profile.replay_gate_vectors(v4, table, vectors, published) == profile.GATE_DECISIONS
    with pytest.raises(ValueError, match="through the published bytes"):
        profile.replay_gate_vectors(v4, table, vectors, changed)


def test_the_restated_block_is_v4s_rule():
    assert profile.readlinkat_block(267).hex() == ("150000050b010000" "2000000010000000" "5400000000000080" "1500000100000000"
                                                   "060000000000ff7f" "0600000000000080")
    assert profile.readlinkat_block(78)[:8].hex() == "150000054e000000"
    assert profile._decode(profile.readlinkat_block(78))[0] == (0x15, 0, 5, 78)
    with pytest.raises(ValueError, match="whole number of instructions"):
        profile._decode(b"\x00" * 7)


@pytest.mark.parametrize("change", ["thirteenth_program", "dropped_row", "absolute_path", "row_path", "row_order", "key_order",
                                    "predecessor", "source", "format", "extra"])
def test_the_index_names_exactly_the_fourteen_programs(monkeypatch, change):
    index = _json(profile.INDEX_PATH)
    rows = index["programs"]
    if change == "thirteenth_program":
        rows.append(dict(rows[0], path=profile.PROGRAMS_DIR + "BROKER.aarch64.bpf"))
    elif change == "dropped_row":
        rows.pop()
    elif change == "absolute_path":
        rows[2]["path"] = "/" + rows[2]["path"]
    elif change == "row_path":
        rows[0]["path"] = rows[0]["path"].replace(profile.PREDECESSOR_DIR, profile.CONTRACT_DIR)
    elif change == "row_order":
        rows[0], rows[1] = rows[1], rows[0]
    elif change == "key_order":
        rows[5] = {"arch": rows[5].pop("arch"), **rows[5]}
    elif change == "predecessor":
        index["predecessor"]["packet"] = "MET-ENFORCE-024"
    elif change == "source":
        index["source"]["files"][profile.V4_MODEL] = "sha256:" + "0" * 64
    elif change == "format":
        index["format"] += "."
    else:
        index["note"] = "x"
    _rebind(monkeypatch, {profile.INDEX_PATH: _dump(index)})
    with pytest.raises(ValueError, match="the index names exactly the fourteen v4 programs at their repository paths"):
        profile.validate_compiled_filter_programs_v2()


@pytest.mark.parametrize("change", ["v2_row_changed", "v2_row_order", "v2_row_dropped", "v2_key_order", "new_consumer_packet",
                                    "new_consumer_path", "new_status", "new_mode", "new_sha", "new_provider_packet",
                                    "third_new_row", "new_row_key", "supersedes", "decision", "rules", "statuses",
                                    "not_artifacts", "note_dropped", "extra_key", "artifact", "schema"])
def test_edge_record_v3_is_v2_plus_exactly_two_rows(monkeypatch, change):
    edge = _json(profile.V3_EDGE)
    rows = edge["artifacts"]
    if change == "v2_row_changed":
        rows[5]["consumerPacket"] = "HE-003"
    elif change == "v2_row_order":
        rows[17], rows[18] = rows[18], rows[17]
    elif change == "v2_row_dropped":
        rows.pop(27)
    elif change == "v2_key_order":
        rows[3] = {"sha256": rows[3].pop("sha256"), **rows[3]}
    elif change == "new_consumer_packet":
        rows[31]["consumerPacket"] = "HE-003A"
    elif change == "new_consumer_path":
        rows[32]["consumerPath"] = rows[32]["consumerPath"].replace("seccomp-v4", "seccomp-v3")
    elif change == "new_status":
        rows[31]["status"] = "IN_USE"
    elif change == "new_mode":
        rows[32]["mode"] = "100755"
    elif change == "new_sha":
        rows[32]["sha256"] = rows[20]["sha256"]
    elif change == "new_provider_packet":
        rows[31]["providerPacket"] = "MET-ENFORCE-025"
    elif change == "third_new_row":
        rows.append(dict(rows[31]))
    elif change == "new_row_key":
        rows[31]["note"] = "x"
    elif change == "supersedes":
        edge["supersedes"]["sha256"] = "sha256:" + "0" * 64
    elif change == "decision":
        edge["ownerDecisions"][2] = edge["ownerDecisions"][2].replace("HE-003A2", "HE-003A")
    elif change == "rules":
        edge["rules"].pop()
    elif change == "statuses":
        edge["statuses"]["RETIRED"] = "x"
    elif change == "not_artifacts":
        edge["notArtifacts"] = []
    elif change == "note_dropped":
        edge["notes"].pop()
    elif change == "extra_key":
        edge["retired"] = []
    elif change == "artifact":
        edge["artifact"] += "-2"
    else:
        edge["schemaVersion"] = "planeon.internal.artifact-edge-registry/v3"
    _rebind(monkeypatch, {profile.V3_EDGE: _dump(edge)})
    with pytest.raises(ValueError, match="edge record v3 is v2's 31 rows plus exactly the two EFFECT_GATE rows"):
        profile.validate_compiled_filter_programs_v2()


def test_a_changed_v2_row_cannot_follow_into_v3(monkeypatch):
    v2, v3 = _json(profile.V2_EDGE), _json(profile.V3_EDGE)
    for edge in (v2, v3):
        edge["artifacts"][8]["consumerPacket"] = "HE-003"
    v2_raw = _dump(v2)
    v3["supersedes"]["sha256"] = "sha256:" + profile.digest(v2_raw)
    _rebind(monkeypatch, {profile.V2_EDGE: v2_raw, profile.V3_EDGE: _dump(v3)})
    with pytest.raises(ValueError, match="edge record v2 is the one v3 supersedes"):
        profile.validate_compiled_filter_programs_v2()


def test_each_provider_path_is_registered_once(monkeypatch):
    v2, v3 = _json(profile.V2_EDGE), _json(profile.V3_EDGE)
    for edge in (v2, v3):
        edge["artifacts"][30] = dict(edge["artifacts"][29])
    v2_raw = _dump(v2)
    v3["supersedes"]["sha256"] = "sha256:" + profile.digest(v2_raw)
    monkeypatch.setattr(profile, "V2_EDGE_SHA256", profile.digest(v2_raw))
    _rebind(monkeypatch, {profile.V2_EDGE: v2_raw, profile.V3_EDGE: _dump(v3)})
    with pytest.raises(ValueError, match="each provider path is registered once"):
        profile.validate_compiled_filter_programs_v2()


@pytest.mark.parametrize("path", ["ci/network_canary.py", "architecture/i07-policy-write-v3/vectors.json", OLD_BROKER, GATE_X86])
def test_a_registered_artifact_must_match_its_provider_bytes(monkeypatch, path):
    original = profile.reviewed_bytes
    if path in profile.ERA_SHA256:
        # An era file is refused by its digest binding before the edge record is read.
        monkeypatch.setattr(profile, "reviewed_bytes", lambda target: _flip(original(target)) if target == path else original(target))
        with pytest.raises(ValueError, match=re.escape("unreviewed compiled filter programs v2 source: " + path)):
            profile.validate_compiled_filter_programs_v2()
        return
    monkeypatch.setattr(profile, "reviewed_bytes", lambda target: _flip(original(target)) if target == path else original(target))
    with pytest.raises(ValueError, match=re.escape("a registered artifact matches its provider bytes: " + path)):
        profile.validate_compiled_filter_programs_v2()


def test_an_edge_that_could_close_a_cycle_is_refused(monkeypatch):
    monkeypatch.setattr(profile, "_no_cycle", lambda registry, consumer: False)
    with pytest.raises(ValueError, match="the edge cannot close a cycle"):
        profile.validate_compiled_filter_programs_v2()


def test_the_registry_rule_reads_every_graph():
    registry = {"repositories": [{"id": "operator"}, {"id": "harness-engineering"}],
                "dependencyGraphs": {"g": {"edges": [{"consumer": "harness-engineering", "provider": "operator"}]}}}
    assert profile._no_cycle(registry, "operator") is False
    registry["dependencyGraphs"]["g"]["edges"] = []
    assert profile._no_cycle(registry, "operator") is True
    assert profile._no_cycle(registry, "conformance-labs") is False


def test_the_decision_texts_come_from_the_hs43_record(monkeypatch):
    hs43 = _json(profile.HS43_RECORD)
    texts = profile._decision_texts(hs43)
    assert texts["Q-HE3A-1"] == ("(c) readlink exe for the I07 writer",) * 2
    assert texts["Q-HE3D-3"] == ("(a): " + profile.Q_HE3D_3, profile.Q_HE3D_3)
    next(row for row in hs43["ownerDecisions"] if row["id"] == "Q-HE3A-1b")["date"] = "2026-10-14"
    with pytest.raises(ValueError, match="the HS43 record's owner decision Q-HE3A-1b"):
        profile._decision_texts(hs43)


def test_a_later_successor_leaves_this_era_valid_through_projection(monkeypatch):
    original, reviewed = profile.regular_bytes, profile.reviewed_bytes
    paths = (profile.INDEX_PATH, profile.V4_MODEL, profile.V2_EDGE)
    era = {path: reviewed(path) for path in paths}
    later = {profile.INDEX_PATH: era[profile.INDEX_PATH].replace(b'"DATA_CHECK_ONLY"', b'"DATA_CHECK_LATER"', 1),
             profile.V4_MODEL: era[profile.V4_MODEL] + b"\nraise ValueError('later module')\n",
             profile.V2_EDGE: era[profile.V2_EDGE] + b"\n"}
    monkeypatch.setattr(profile, "regular_bytes", lambda path: later.get(path) or original(path))
    with pytest.raises(ValueError):
        profile.validate_compiled_filter_programs_v2()
    monkeypatch.setattr(profile, "reviewed_bytes", lambda path: era[path] if path in later else reviewed(path))
    assert profile.validate_compiled_filter_programs_v2() is None
    # A later file in the contract directory is projected away through reviewed_tree.
    tree = profile.reviewed_tree(profile.CONTRACT_DIR)
    monkeypatch.setattr(profile, "reviewed_tree", lambda directory: {**tree, profile.CONTRACT_DIR + "later.json": 0o100644})
    with pytest.raises(ValueError, match="holds exactly its seven files"):
        profile.validate_compiled_filter_programs_v2()
    monkeypatch.setattr(profile, "reviewed_tree", lambda directory: tree)
    assert profile.validate_compiled_filter_programs_v2() is None


def test_reviewed_bytes_is_the_only_semantic_read():
    tree = ast.parse(profile.regular_bytes(profile.VALIDATOR_PATH))
    names = {"_verified", "_json", "_holds", "_bound", "_era_model", "_decision_texts", "readlinkat_block", "_decode",
             "validate_contract_files", "validate_status", "validate_readmes", "validate_programs", "replay_gate_vectors",
             "_no_cycle", "validate_edge_record", "validate_compiled_filter_programs_v2"}
    seen = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            seen.add(node.name)
            used = {name.id for name in ast.walk(node) if isinstance(name, ast.Name)}
            attributes = {attribute.attr for attribute in ast.walk(node) if isinstance(attribute, ast.Attribute)}
            assert not used & {"regular_bytes", "open"}, node.name
            assert not attributes & {"read_bytes", "read_text", "open", "lstat", "stat", "iterdir", "glob", "rglob"}, node.name
    assert seen == names
