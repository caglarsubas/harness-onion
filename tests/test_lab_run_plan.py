"""Exact source lineage for MET-LINUX-007; lab run-plan contract v1: closed schemas for a qualification run plan on the owner's GCP compute, its lease and its teardown-residual report, restated independently of the offline checker, every positive plan sha256 recomputed and the checker replaying every vector from its reviewed bytes, checked in the validator."""
import ast
import json
import copy
from copy import deepcopy
import os
import re
import stat
import types
from pathlib import Path
from types import MappingProxyType

import pytest

from scripts import validate_lab_run_plan as profile
from scripts import validate_w03_plan_amend_3 as wpa3
from scripts import validate_compiled_filter_programs_v3 as cfp3
from scripts import validate_seccomp_observer_listener as sol
from scripts import validate_selinux_matrix_v4 as mx6
from scripts import validate_native_profile_v4 as np4
from scripts import validate_topology_coordination as tcv1
from scripts import validate_w03_plan_amend_2 as wpa2
from scripts import validate_license_amendment_v2 as la2
from scripts import validate_i05_gate_channel_v4 as i5v4
from scripts import validate_chain_depth_headroom as cdh
from scripts import validate_compiled_filter_programs_v2 as cfp2
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
    # The newer MET-ENFORCE-038 layer is projected away before this layer's payload checks.
    return profile.successor.historical_catalog(packets())


def changed_test():
    return next(path for path in profile._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert profile.validate() is None
    current = packets()
    accepted = profile.historical_catalog(current)
    assert len(current) == 272 and len(accepted) == 250
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
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET}
    assert len(wpa3.historical_catalog(current)) == 249
    assert len(cfp3.historical_catalog(current)) == 248
    assert len(sol.historical_catalog(current)) == 247
    assert len(mx6.historical_catalog(current)) == 246
    assert len(np4.historical_catalog(current)) == 245
    assert len(tcv1.historical_catalog(current)) == 244
    assert len(wpa2.historical_catalog(current)) == 243
    assert len(la2.historical_catalog(current)) == 242
    assert len(i5v4.historical_catalog(current)) == 241
    assert len(cdh.historical_catalog(current)) == 240
    assert len(cfp2.historical_catalog(current)) == 239
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
    wpa3_before = wpa3.historical_bytes(path, current)
    assert wpa3.current_test_bytes(wpa3_before) == current
    cfp3_before = cfp3.historical_bytes(path, current)
    assert cfp3.current_test_bytes(cfp3_before) == current
    sol_before = sol.historical_bytes(path, current)
    assert sol.current_test_bytes(sol_before) == current
    mx6_before = mx6.historical_bytes(path, current)
    assert mx6.current_test_bytes(mx6_before) == current
    np4_before = np4.historical_bytes(path, current)
    assert np4.current_test_bytes(np4_before) == current
    tcv1_before = tcv1.historical_bytes(path, current)
    assert tcv1.current_test_bytes(tcv1_before) == current
    wpa2_before = wpa2.historical_bytes(path, current)
    assert wpa2.current_test_bytes(wpa2_before) == current
    la2_before = la2.historical_bytes(path, current)
    assert la2.current_test_bytes(la2_before) == current
    i5v4_before = i5v4.historical_bytes(path, current)
    assert i5v4.current_test_bytes(i5v4_before) == current
    cdh_before = cdh.historical_bytes(path, current)
    assert cdh.current_test_bytes(cdh_before) == current
    cfp2_before = cfp2.historical_bytes(path, current)
    assert cfp2.current_test_bytes(cfp2_before) == current
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


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "wpa3_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = profile.historical_bytes(path, raw) if route in ("current_test", "old_bytes") else None
    current_packets = packets() if route == "catalog" else None
    layer = layer_packets() if route == "payloads" else None
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
    old_wpa3 = wpa3.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "wpa3_old" else None
    old_cfp3 = cfp3.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "cfp3_old" else None
    old_sol = sol.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "sol_old" else None
    old_mx6 = mx6.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "mx6_old" else None
    old_np4 = np4.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "np4_old" else None
    old_tcv1 = tcv1.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "tcv1_old" else None
    old_wpa2 = wpa2.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "wpa2_old" else None
    old_la2 = la2.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "la2_old" else None
    old_i5v4 = i5v4.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "i5v4_old" else None
    old_cdh = cdh.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "cdh_old" else None
    old_cfp2 = cfp2.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "cfp2_old" else None
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
        "wpa3_old": lambda: wpa3.historical_bytes(roadmap.MASTER_PATH, old_wpa3),
        "cfp3_old": lambda: cfp3.historical_bytes(roadmap.MASTER_PATH, old_cfp3),
        "sol_old": lambda: sol.historical_bytes(roadmap.MASTER_PATH, old_sol),
        "mx6_old": lambda: mx6.historical_bytes(roadmap.MASTER_PATH, old_mx6),
        "np4_old": lambda: np4.historical_bytes(roadmap.MASTER_PATH, old_np4),
        "tcv1_old": lambda: tcv1.historical_bytes(roadmap.MASTER_PATH, old_tcv1),
        "wpa2_old": lambda: wpa2.historical_bytes(roadmap.MASTER_PATH, old_wpa2),
        "la2_old": lambda: la2.historical_bytes(roadmap.MASTER_PATH, old_la2),
        "i5v4_old": lambda: i5v4.historical_bytes(roadmap.MASTER_PATH, old_i5v4),
        "cdh_old": lambda: cdh.historical_bytes(roadmap.MASTER_PATH, old_cdh),
        "cfp2_old": lambda: cfp2.historical_bytes(roadmap.MASTER_PATH, old_cfp2),
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
    with pytest.raises(ValueError, match="lab run-plan history authority digest"):
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
    assert len(profile.historical_catalog(current)) == 250


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
    assert len(profile.historical_catalog(current)) == 250
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
    assert len(rules) == 251 and len(parsed) == 250
    assert profile._packet_rules() is rules and len(parsed) == 250
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
    with pytest.raises(ValueError, match="lab run-plan history authority digest"):
        profile.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = layer_packets()
    profile.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "lab-run-plan-authority.json").write_bytes(
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
    # The newer MET-ENFORCE-038 layer refuses a mutated validator before this layer.
    with pytest.raises(ValueError, match="unreviewed current source: scripts/validate_lab_run_plan.py"):
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
            assert all("validate_" not in alias.name or alias.name == "validate_native_profile_v5"
                       for alias in node.names)


def _count_authority_reads(monkeypatch):
    counts = {}
    for module in (profile.successor, profile, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner):
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
    expected = {module.__name__: 1 for module in (profile.successor, profile, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner)}
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


LAST_RECORD = profile.REVIEW_RECORDS[-1]
VALIDATE = profile.validate_lab_run_plan


def test_the_contract_holds_for_this_era():
    assert VALIDATE() is None


def test_every_contract_file_is_pinned():
    assert set(profile.ERA_SHA256) == set(profile.NEW_FILES)
    assert set(profile.REVIEWED_SHA256) == set(profile.CONTRACT_FILES) - {profile.STATUS_PATH}
    assert len(profile.CONTRACT_FILES) == 8 and profile.CHECKER in profile.CONTRACT_FILES
    for path, expected in profile.ERA_SHA256.items():
        assert profile.digest(profile.regular_bytes(path)) == expected


@pytest.mark.parametrize("path", sorted(profile.ERA_SHA256))
def test_every_era_file_is_bound_by_digest_before_anything_runs(monkeypatch, path):
    original = profile.reviewed_bytes
    executed = []
    monkeypatch.setattr(profile, "reviewed_bytes", lambda target: original(target) + b" " if target == path else original(target))
    monkeypatch.setattr(profile, "_era_model", lambda *args: executed.append(args[0]))
    with pytest.raises(ValueError, match=re.escape("unreviewed lab run-plan source: " + path)):
        VALIDATE()
    assert executed == []


def test_a_path_outside_the_era_is_refused_before_it_is_read():
    with pytest.raises(ValueError, match="MET-LINUX-007 reviewed bytes are bound: README.md"):
        profile._verified("README.md")


@pytest.mark.parametrize("path", [profile.FROZEN_PATHS[0], profile.FROZEN_PATHS[len(profile.FROZEN_PATHS) // 2],
                                  profile.FROZEN_PATHS[-1], profile.REPOSITORIES])
def test_the_edge_records_and_the_registry_may_not_be_changed_by_this_packet(monkeypatch, path):
    assert path in profile.FROZEN_PATHS
    rules = dict(profile._PROJECTION_RULES)
    rules[path] = {"beforeSha256": "0" * 64, "afterSha256": "0" * 64}
    monkeypatch.setattr(profile, "_PROJECTION_RULES", MappingProxyType(rules))
    with pytest.raises(ValueError, match="stay byte-identical"):
        VALIDATE()


def test_the_frozen_set_is_the_edge_records_and_the_registry():
    """Constant checks only, so a later packet that adds an edge record leaves this test valid."""
    frozen = set(profile.FROZEN_PATHS)
    assert len(frozen) == len(profile.FROZEN_PATHS) == 14 and profile.REPOSITORIES in frozen
    assert all(path.startswith(profile.FROZEN_DIRS) for path in frozen - {profile.REPOSITORIES})
    assert {profile.EDGES_DIR + "README.md", profile.EDGES_DIR + "operator-harness-engineering.json",
            profile.EDGES_DIR + "operator-harness-engineering-v6.json",
            profile.EDGES_DIR + "conformance-labs-harness-engineering.json"} <= frozen
    assert not frozen & set(profile.NEW_FILES)
    assert all((profile.ROOT / path).is_file() for path in frozen)


@pytest.mark.parametrize("path", ["architecture/artifact-edges/conformance-labs-harness-engineering-v2.json",
                                  "architecture/artifact-edges/README-lab-run-plan.md"])
def test_no_edge_record_may_be_added_by_this_packet(monkeypatch, path):
    record = copy.deepcopy(profile.authority())
    record["newFiles"][path] = "0" * 64
    monkeypatch.setattr(profile, "authority", lambda: record)
    with pytest.raises(ValueError, match="stay byte-identical"):
        VALIDATE()


@pytest.mark.parametrize("change", ["missing_checker", "missing_record", "contract_extra"])
def test_the_contract_files_are_new_in_this_packet_each_once(monkeypatch, change):
    record = copy.deepcopy(profile.authority())
    if change == "missing_checker":
        del record["newFiles"][profile.CHECKER]
    elif change == "missing_record":
        del record["newFiles"][LAST_RECORD]
    else:
        record["newFiles"][profile.CONTRACT_DIR + "review-round9.json"] = "0" * 64
    monkeypatch.setattr(profile, "authority", lambda: record)
    with pytest.raises(ValueError, match="the contract's files are new in this packet, each once"):
        VALIDATE()


def _tree_copy(tmp_path):
    """The contract's files under tmp_path, as git checks out mode 100644."""
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
    assert VALIDATE() is None


@pytest.mark.parametrize("change, message", [
    ("schema_symlink", "a contract file is a regular file of git mode 100644: " + profile.PLAN_SCHEMA),
    ("vectors_executable", "a contract file is a regular file of git mode 100644: " + profile.VECTORS_PATH),
    ("checker_executable", "a contract file is a regular file of git mode 100644: " + profile.CHECKER),
    ("checker_symlink", "a contract file is a regular file of git mode 100644: " + profile.CHECKER),
    ("extra_file", "the contract directory holds exactly its files"),
    ("missing_file", "the contract directory holds exactly its files"),
    ("sub_directory", "the contract directory holds exactly its files"),
    ("linked_directory", "the contract directory is a directory, not a link"),
])
def test_the_contract_tree_is_closed_and_every_file_is_mode_100644(tmp_path, monkeypatch, change, message):
    root = _tree_copy(tmp_path / "tree")
    contract = root / profile.CONTRACT_DIR
    outside = tmp_path / "outside"
    outside.mkdir()
    if change == "schema_symlink":
        (outside / "schema").write_bytes((root / profile.PLAN_SCHEMA).read_bytes())
        (root / profile.PLAN_SCHEMA).unlink()
        (root / profile.PLAN_SCHEMA).symlink_to(outside / "schema")
    elif change == "vectors_executable":
        (root / profile.VECTORS_PATH).chmod(0o755)
    elif change == "checker_executable":
        (root / profile.CHECKER).chmod(0o744)
    elif change == "checker_symlink":
        (outside / "checker.py").write_bytes((root / profile.CHECKER).read_bytes())
        (root / profile.CHECKER).unlink()
        (root / profile.CHECKER).symlink_to(outside / "checker.py")
    elif change == "extra_file":
        (contract / ".notes").write_bytes(b"x")
    elif change == "missing_file":
        (contract / "REVIEW_BRIEF.md").unlink()
    elif change == "sub_directory":
        (contract / "examples").mkdir()
    else:
        contract.rename(outside / "contract")
        (root / profile.CONTRACT_DIR[:-1]).symlink_to(outside / "contract", target_is_directory=True)
    _serve_tree(monkeypatch, root)
    with pytest.raises(ValueError, match=re.escape(message)):
        VALIDATE()


def test_the_tree_readers_report_links_and_modes(tmp_path, monkeypatch):
    root = _tree_copy(tmp_path)
    (root / profile.CONTRACT_DIR / "link").symlink_to(root / profile.VECTORS_PATH)
    monkeypatch.setattr(profile, "ROOT", root)
    tree = profile.reviewed_tree(profile.CONTRACT_DIR)
    assert set(tree) == profile.CONTRACT_TREE | {profile.CONTRACT_DIR + "link"}
    assert stat.S_ISLNK(tree[profile.CONTRACT_DIR + "link"])
    assert stat.S_IMODE(profile.reviewed_mode(profile.CHECKER)) == 0o644
    with pytest.raises(ValueError, match="relative source path"):
        profile.reviewed_mode("../outside")


# Synthetic local paths, assembled so this file holds none: the markers the check refuses, each followed by a path.
LOCAL = [b"/Us" + b"ers/someone/x", b"/pri" + b"vate/tmp/x", b"/ho" + b"me/someone/x", b"~/.local/st" + b"ate/x",
         b"/tmp/cla" + b"ude-000/x", b"/US" + b"ERS/someone/x", b"/Us" + b"ers/\xc3\xa7a/x"]


@pytest.mark.parametrize("local", LOCAL)
@pytest.mark.parametrize("path", [profile.README_PATH, LAST_RECORD])
def test_no_contract_file_may_carry_an_absolute_local_path(monkeypatch, path, local):
    if path.endswith(".md"):
        raw = profile.reviewed_bytes(path) + b"\nsee " + local + b"\n"
    else:
        record = _json(path)
        record["checked"].append("see " + local.decode("utf-8"))
        raw = _dump(record)
    _rebind(monkeypatch, {path: raw})
    if path == LAST_RECORD:
        status = _json(profile.STATUS_PATH)
        status["reviewRounds"][-1]["recordSha256"] = "sha256:" + profile.digest(raw)
        _rebind(monkeypatch, {path: raw, profile.STATUS_PATH: _dump(status)})
    with pytest.raises(ValueError, match=re.escape("no absolute local path in a contract file: " + path)):
        VALIDATE()


def test_a_quoted_hygiene_pattern_is_not_a_path():
    assert profile.local_paths(b"hygiene: no /Us" + b"ers/, /pri" + b"vate/, /ho" + b"me/, /tmp/ or ~/ path") == []
    assert profile.local_paths(b"under <scratch>/example/ and <worktree>/scripts/") == []
    assert [m for m, _ in profile.local_paths(b"under /pri" + b"vate/tmp/example/")] == [b"/private/"]


@pytest.mark.parametrize("change, message", [
    ("state", "adopted MET-LINUX-007 status"),
    ("packet", "adopted MET-LINUX-007 status"),
    ("schema", "adopted MET-LINUX-007 status"),
    ("roadmap", "adopted MET-LINUX-007 status"),
    ("evidence", "adopted MET-LINUX-007 status"),
    ("base", "adopted MET-LINUX-007 status"),
    ("contract_files", "adopted MET-LINUX-007 status"),
    ("extra", "adopted MET-LINUX-007 status"),
    ("key_order", "adopted MET-LINUX-007 status"),
    ("carried", "adopted MET-LINUX-007 status"),
    ("clean_room", "adopted MET-LINUX-007 status"),
    ("not_published", "adopted MET-LINUX-007 status"),
    ("consumers", "adopted MET-LINUX-007 status"),
    ("consumers_edge", "adopted MET-LINUX-007 status"),
    ("independence", "adopted MET-LINUX-007 status"),
    ("cloud_run", "adopted MET-LINUX-007 status"),
    ("credentials", "adopted MET-LINUX-007 status"),
    ("adoption_edit", "adopted MET-LINUX-007 status"),
    ("decision_text", "the decisions, verbatim"),
    ("decision_monitor", "the decisions, verbatim"),
    ("decision_order", "the decisions, verbatim"),
    ("decision_date", "the decisions, verbatim"),
    ("decision_source", "the decisions, verbatim"),
    ("decision_missing", "the decisions, verbatim"),
    ("round_verdict", "every review round is bound to its record and subject"),
    ("round_subject", "every review round is bound to its record and subject"),
    ("round_base", "every review round is bound to its record and subject"),
    ("round_record", "every review round is bound to its record and subject"),
    ("round_findings", "every review round is bound to its record and subject"),
    ("extra_round", "every review round is bound to its record and subject"),
])
def test_a_status_field_change_is_refused(monkeypatch, change, message):
    status = _json(profile.STATUS_PATH)
    if change == "state":
        status["contractState"] = "CANDIDATE"
    elif change == "packet":
        status["packet"] = "MET-LINUX-006"
    elif change == "schema":
        status["schemaVersion"] = "planeon.internal.met-linux-006-status/v1"
    elif change == "roadmap":
        status["roadmapItem"] = "CONF-LINUX-001"
    elif change == "evidence":
        status["evidenceClass"] = "NATIVE_RUN"
    elif change == "base":
        status["base"] = "0" * 40
    elif change == "contract_files":
        status["contractFiles"].append(LAST_RECORD)
    elif change == "extra":
        status["runApproved"] = True
    elif change == "key_order":
        status = {"packet": status.pop("packet"), **status}
    elif change == "carried":
        status["carriedNotes"]["X-1"] = "an unrecorded note"
    elif change == "clean_room":
        status["cleanRoom"] = "designed from the owner's lab repository"
    elif change == "not_published":
        status["notPublished"].pop()
    elif change == "consumers":
        status["consumers"]["R10"] = "none"
    elif change == "consumers_edge":
        status["consumers"]["R12"] = "CONF-LINUX-001 and W06 run plans; an edge record now"
    elif change == "independence":
        status["reviewerIndependence"] = "AUTHOR"
    elif change == "cloud_run":
        status["cloudRunExecuted"] = True
    elif change == "credentials":
        status["credentialsHandled"] = None
    elif change == "adoption_edit":
        status["adoptionEdit"] = ""
    elif change == "decision_text":
        status["ownerDecisions"][0]["decision"] = status["ownerDecisions"][0]["decision"].replace("Q-RP-4 (a)", "Q-RP-4 (b)")
    elif change == "decision_monitor":
        status["ownerDecisions"][3]["decision"] = status["ownerDecisions"][3]["decision"].replace("18", "17", 1)
    elif change == "decision_order":
        status["ownerDecisions"].reverse()
    elif change == "decision_date":
        status["ownerDecisions"][2]["date"] = "2026-10-19"
    elif change == "decision_source":
        status["ownerDecisions"][1]["source"] = "owner"
    elif change == "decision_missing":
        status["ownerDecisions"].pop()
    elif change == "round_verdict":
        status["reviewRounds"][-1]["verdict"] = "CHANGES_REQUIRED"
    elif change == "round_subject":
        status["reviewRounds"][-1]["subject"]["tree"] = "0" * 40
    elif change == "round_base":
        status["reviewRounds"][0]["subject"]["base"] = "0" * 40
    elif change == "round_record":
        status["reviewRounds"][-1]["recordSha256"] = "sha256:" + "0" * 64
    elif change == "round_findings":
        status["reviewRounds"][-1]["findings"].append("X-1 NOTE")
    else:
        status["reviewRounds"].append(dict(status["reviewRounds"][-1], round=len(status["reviewRounds"]) + 1))
    _rebind(monkeypatch, {profile.STATUS_PATH: _dump(status)})
    with pytest.raises(ValueError, match=re.escape(message)):
        VALIDATE()


@pytest.mark.parametrize("change", ["severity", "verdict", "subject", "base", "finding_added", "finding_key", "checked",
                                    "record_key"])
def test_each_review_record_is_its_rounds(monkeypatch, change):
    record = _json(LAST_RECORD)
    if change == "severity":
        record["findings"].append({"id": "X-1", "severity": "MINOR", "file": "x", "line": 1, "summary": "x",
                                   "evidence": "x"})
    elif change == "verdict":
        record["verdict"] = "CHANGES_REQUIRED"
    elif change == "subject":
        record["subjectCommit"] = "0" * 40
    elif change == "base":
        record["base"] = "0" * 40
    elif change == "finding_added":
        record["findings"].append({"id": "X-1", "severity": "NOTE", "file": "x", "line": 1, "summary": "x",
                                   "evidence": "x"})
    elif change == "finding_key":
        record["findings"].append({"id": "X-1", "severity": "NOTE"})
    elif change == "checked":
        record["checked"] = []
    else:
        record["reviewer"] = "AUTHOR"
    raw = _dump(record)
    status = _json(profile.STATUS_PATH)
    status["reviewRounds"][-1]["recordSha256"] = "sha256:" + profile.digest(raw)
    _rebind(monkeypatch, {LAST_RECORD: raw, profile.STATUS_PATH: _dump(status)})
    with pytest.raises(ValueError, match="the round-%d record is its round's" % profile.ROUNDS[-1][0]):
        VALIDATE()


@pytest.mark.parametrize("change", ["last_changes_required", "last_minor", "earlier_pass"])
def test_the_last_round_passes_with_notes_only(monkeypatch, change):
    """The rounds, their status rows and their records changed together, so only the final check can refuse them."""
    number = 0 if change == "earlier_pass" else -1
    rounds = [list(row) for row in profile.ROUNDS]
    record_path = rounds[number][1]
    record = _json(record_path)
    if change == "last_changes_required":
        record["verdict"] = "CHANGES_REQUIRED"
    elif change == "last_minor":
        record["findings"].append({"id": "X-1", "severity": "MINOR", "file": "x", "line": 1, "summary": "x",
                                   "evidence": "x"})
    else:
        record["verdict"] = "PASS_FOR_SOURCE_PUBLICATION"
    raw = _dump(record)
    rounds[number][4] = record["verdict"]
    rounds[number][5] = tuple((row["id"], row["severity"]) for row in record["findings"])
    status = _json(profile.STATUS_PATH)
    row = status["reviewRounds"][number]
    row["verdict"] = record["verdict"]
    row["findings"] = ["%s %s" % finding for finding in rounds[number][5]]
    row["recordSha256"] = "sha256:" + profile.digest(raw)
    monkeypatch.setattr(profile, "ROUNDS", tuple(tuple(row) for row in rounds))
    _rebind(monkeypatch, {record_path: raw, profile.STATUS_PATH: _dump(status)})
    with pytest.raises(ValueError, match="the last round passes with notes only"):
        VALIDATE()


def test_the_decision_texts_are_the_relayed_messages():
    texts = profile.DECISION_TEXTS
    assert tuple(texts) == tuple(name for name, _date, _source in profile.DECISIONS)
    assert texts["Q-RP-0..9"].startswith("Monitor relay, owner decisions on LAB-RUNPLAN-001, 2026-10-19:\n- Q-RP-0 (a)")
    assert texts["Q-RP-0..9"].endswith("The pre-check, dry run and push need my word.")
    assert texts["MON-18-CLASSES-KEEP-R1"].startswith("Monitor: keep the 18 resource classes.")
    assert texts["MON-R3-KEEP-IF-OWN-NOTES"].startswith("Monitor: (a) keep round 3, on one condition.")


@pytest.mark.parametrize("path", [profile.README_PATH, profile.PLAN_SCHEMA, profile.VECTORS_PATH, profile.CHECKER,
                                  profile.REVIEW_BRIEF_PATH])
def test_the_adopted_contract_is_the_reviewed_subject(monkeypatch, path):
    _rebind(monkeypatch, {path: profile.reviewed_bytes(path) + b"\n"}, reviewed=False)
    with pytest.raises(ValueError, match=re.escape("the adopted contract is the reviewed subject: " + path)):
        VALIDATE()


@pytest.mark.parametrize("path, old, new, message", [
    (profile.README_PATH, b"Status: **CONTRACT_CANDIDATE_AWAITING_INDEPENDENT_REVIEW**", b"Status: **ADOPTED**",
     "the README keeps its candidate status line: " + profile.README_PATH),
    (profile.README_PATH, b"\n## Decisions", b"\nStatus: **ADOPTED**\n\n## Decisions",
     "the README keeps its candidate status line: " + profile.README_PATH),
    (profile.README_PATH, b"(MET-LINUX-007)\n", b"(MET-LINUX-008)\n",
     "the README keeps its candidate status line: " + profile.README_PATH),
    (profile.LEASE_SCHEMA, b"\n", b"\n\"MET-LINUX-007\"\n", "MET-LINUX-007 is written in exactly the restated contract files"),
    (profile.CHECKER, b"MET-LINUX-007", b"MET-LINUX-008", "MET-LINUX-007 is written in exactly the restated contract files"),
])
def test_the_readme_status_line_and_the_packet_id_are_restated(monkeypatch, path, old, new, message):
    raw = profile.reviewed_bytes(path)
    assert raw.count(old) >= 1
    _rebind(monkeypatch, {path: raw.replace(old, new, 1)})
    with pytest.raises(ValueError, match=re.escape(message)):
        VALIDATE()


def test_the_naming_files_are_the_documents_that_name_the_packet():
    assert {profile.README_PATH, profile.STATUS_PATH, profile.CHECKER} <= profile.NAMING_FILES <= set(profile.NEW_FILES)
    assert profile.LEASE_SCHEMA not in profile.NAMING_FILES


# The schemas ---------------------------------------------------------------------------------------------------------

def _rebind_json(monkeypatch, path, value):
    _rebind(monkeypatch, {path: _dump(value)})


@pytest.mark.parametrize("path, change", [
    (profile.PLAN_SCHEMA, "open_object"),
    (profile.PLAN_SCHEMA, "optional_property"),
    (profile.LEASE_SCHEMA, "foreign_keyword"),
    (profile.LEASE_SCHEMA, "dialect"),
    (profile.TEARDOWN_SCHEMA, "items_off_array"),
    (profile.TEARDOWN_SCHEMA, "untyped_object"),
    (profile.TEARDOWN_SCHEMA, "id"),
    (profile.PLAN_SCHEMA, "version_const"),
    (profile.LEASE_SCHEMA, "top_order"),
    (profile.PLAN_SCHEMA, "duplicate_required"),
])
def test_each_schema_is_closed_in_the_subset(monkeypatch, path, change):
    schema = _json(path)
    properties = schema["properties"]
    if change == "open_object":
        properties["observer"]["additionalProperties"] = True
    elif change == "optional_property":
        properties["budget"]["required"].pop()
    elif change == "foreign_keyword":
        properties["startsAt"]["format"] = "date-time"
    elif change == "dialect":
        schema = {"$schema": "https://json-schema.org/draft/2020-12/schema", **schema}
    elif change == "items_off_array":
        properties["kept"]["type"] = "object"
    elif change == "untyped_object":
        del properties["resources"]["type"]
    elif change == "id":
        schema["$id"] = "planeon.internal.lab-run-teardown/v2"
    elif change == "version_const":
        properties["schemaVersion"]["const"] = "planeon.internal.lab-run-plan/v2"
    elif change == "top_order":
        schema = {"title": schema.pop("title"), **schema}
    else:
        schema["required"].append(schema["required"][0])
    _rebind_json(monkeypatch, path, schema)
    with pytest.raises(ValueError, match=re.escape("a closed schema in the subset: " + path)):
        VALIDATE()


@pytest.mark.parametrize("path, change", [
    (profile.PLAN_SCHEMA, "gate_added"),
    (profile.PLAN_SCHEMA, "viewer_role_added"),
    (profile.PLAN_SCHEMA, "keep_added"),
    (profile.PLAN_SCHEMA, "exported_keys"),
    (profile.PLAN_SCHEMA, "alert_only"),
    (profile.PLAN_SCHEMA, "held_by"),
    (profile.PLAN_SCHEMA, "separate_project"),
    (profile.PLAN_SCHEMA, "scope"),
    (profile.TEARDOWN_SCHEMA, "class_dropped"),
    (profile.TEARDOWN_SCHEMA, "class_order"),
    (profile.TEARDOWN_SCHEMA, "negative_count"),
    (profile.TEARDOWN_SCHEMA, "kept_added"),
    (profile.TEARDOWN_SCHEMA, "payload"),
])
def test_the_schemas_restate_the_gates_roles_and_classes(monkeypatch, path, change):
    schema = _json(path)
    properties = schema["properties"]
    if change == "gate_added":
        properties["purpose"]["properties"]["gate"]["enum"].append("ANY")
    elif change == "viewer_role_added":
        properties["observer"]["properties"]["roles"]["items"]["enum"].append("roles/owner")
    elif change == "keep_added":
        properties["teardown"]["properties"]["keep"]["items"]["enum"].append("INSTANCES")
    elif change == "exported_keys":
        properties["observer"]["properties"]["exportedKeys"] = {"type": "boolean"}
    elif change == "alert_only":
        properties["budget"]["properties"]["alertOnly"] = {"const": False}
    elif change == "held_by":
        properties["credentials"]["properties"]["heldBy"] = {"const": "RUNNER"}
    elif change == "separate_project":
        properties["project"]["properties"]["separateFromLabFoundation"] = {"type": "boolean"}
    elif change == "scope":
        properties["observer"]["properties"]["scope"] = {"enum": ["RUN_PROJECT", "ORGANISATION"]}
    elif change == "class_dropped":
        properties["resources"]["required"].remove("IAM_BINDINGS_ADDED")
        del properties["resources"]["properties"]["IAM_BINDINGS_ADDED"]
    elif change == "class_order":
        properties["resources"]["required"].reverse()
        properties["resources"]["properties"] = dict(reversed(list(properties["resources"]["properties"].items())))
    elif change == "negative_count":
        properties["resources"]["properties"]["DISKS"] = {"type": "integer", "minimum": -1}
    elif change == "kept_added":
        properties["kept"]["items"]["enum"].append("DISKS")
    else:
        properties["payloadFree"] = {"type": "boolean"}
    _rebind_json(monkeypatch, path, schema)
    with pytest.raises(ValueError, match="the schemas restate the gates, viewer roles, residual and resource classes"):
        VALIDATE()


def test_the_restated_subset_is_closed():
    closed = {"type": "object", "additionalProperties": False, "required": ["a"], "properties": {"a": {"type": "string"}}}
    assert profile._closed(closed)
    assert not profile._closed(dict(closed, required=["a", "a"]))
    assert not profile._closed(dict(closed, required=[]))
    assert not profile._closed({"properties": {}, "required": [], "additionalProperties": False})
    assert not profile._closed({"type": "object"})
    assert not profile._closed({"type": "array", "items": {"type": "object"}})
    assert profile._closed({"type": "array", "items": {"enum": ["x"]}})
    assert not profile._closed({"type": "string", "items": {"enum": ["x"]}})
    assert not profile._closed({"type": "string", "format": "uri"})
    assert not profile._closed(["type"])


# The vectors ---------------------------------------------------------------------------------------------------------

def _vectors():
    return _json(profile.VECTORS_PATH)


def _repin(monkeypatch, vectors, index):
    """Re-bind positive index's lease and report to its changed plan and restate its sha256, so only the check behind
    the sha binding can refuse it."""
    positive = vectors["positives"][index]
    sha = profile.digest(profile.canonical(positive["plan"]))
    positive["lease"]["planSha256"] = positive["teardown"]["planSha256"] = sha
    rows = list(profile.POSITIVES)
    rows[index] = (rows[index][0], rows[index][1], sha)
    monkeypatch.setattr(profile, "POSITIVES", tuple(rows))
    _rebind(monkeypatch, {profile.VECTORS_PATH: _dump(vectors)})


def test_each_positive_plan_sha256_is_recomputed_here():
    vectors = _vectors()
    for row, (name, gate, sha) in zip(vectors["positives"], profile.POSITIVES):
        assert row["id"] == name and row["plan"]["purpose"]["gate"] == gate
        raw = json.dumps(row["plan"], sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        assert profile.digest(raw) == sha == row["lease"]["planSha256"] == row["teardown"]["planSha256"]
    assert [gate for _name, gate, _sha in profile.POSITIVES] == list(profile.GATES)


@pytest.mark.parametrize("change", ["plan_edited", "lease_other_plan", "report_other_lease", "report_observer",
                                    "report_prefix", "class_left", "class_order", "kept_beyond_plan", "kept_no_observer",
                                    "gate"])
def test_each_positive_is_bound_to_its_recomputed_plan_sha256(monkeypatch, change):
    vectors = _vectors()
    positive = vectors["positives"][1]
    plan, lease, report = positive["plan"], positive["lease"], positive["teardown"]
    if change == "plan_edited":
        plan["purpose"]["summary"] += " (edited)"
    elif change == "lease_other_plan":
        lease["planId"] = vectors["positives"][0]["plan"]["planId"]
    elif change == "report_other_lease":
        report["leaseId"] = vectors["positives"][0]["lease"]["leaseId"]
    elif change == "report_observer":
        report["observer"] = "obs-someone-else"
    elif change == "report_prefix":
        report["namePrefix"] = "run-other-"
    elif change == "class_left":
        report["resources"]["DISKS"] = 1
    elif change == "class_order":
        report["resources"] = dict(reversed(list(report["resources"].items())))
    elif change == "kept_beyond_plan":
        report["kept"].append("INSTANCES")
    elif change == "kept_no_observer":
        report["kept"].remove("OBSERVER_IDENTITY")
    else:
        plan["purpose"]["gate"] = "CONF-LINUX-001"
        _repin(monkeypatch, vectors, 1)
    if change != "gate":
        _rebind(monkeypatch, {profile.VECTORS_PATH: _dump(vectors)})
    with pytest.raises(ValueError, match="positive P1 is bound to its recomputed plan sha256"):
        VALIDATE()


def test_each_positive_observer_holds_the_roles_that_list_every_class(monkeypatch):
    vectors = _vectors()
    vectors["positives"][0]["plan"]["observer"]["roles"].remove("roles/iam.securityReviewer")
    _repin(monkeypatch, vectors, 0)
    with pytest.raises(ValueError, match="positive P0's observer holds the roles that list every class"):
        VALIDATE()


def test_the_restated_class_roles_are_the_observer_roles():
    assert set(profile.CLASS_ROLES) == set(profile.RESOURCE_CLASSES)
    assert {role for roles in profile.CLASS_ROLES.values() for role in roles} == profile.OBSERVER_ROLES
    assert profile.OBSERVER_ROLES < set(profile.VIEWER_ROLES)


@pytest.mark.parametrize("change", ["amount", "unit", "unknown_sku", "total", "ceiling", "duplicate_rate"])
def test_each_positive_cost_recomputes_under_its_ceiling(monkeypatch, change):
    vectors = _vectors()
    cost = vectors["positives"][1]["plan"]["cost"]
    if change == "amount":
        cost["lineItems"][0]["amount"] = round(cost["lineItems"][0]["amount"] + 0.01, 2)
        cost["total"] = round(sum(item["amount"] for item in cost["lineItems"]), 2)
    elif change == "unit":
        cost["lineItems"][0]["unit"] = "gb-month"
    elif change == "unknown_sku":
        cost["lineItems"][0]["sku"] = "n2-standard-4"
    elif change == "total":
        cost["total"] = round(cost["total"] - 0.01, 2)
    elif change == "ceiling":
        cost["ceiling"] = 1
    else:
        cost["rateCard"]["rates"].append(dict(cost["rateCard"]["rates"][0], price=9.5))
    _repin(monkeypatch, vectors, 1)
    with pytest.raises(ValueError, match="positive P1's cost recomputes under its ceiling"):
        VALIDATE()


@pytest.mark.parametrize("change", ["at_sign", "at_sign_key", "project", "repository", "image_project", "approval",
                                    "project_twice", "project_in_lease"])
def test_each_positive_carries_only_invented_identifiers(monkeypatch, change):
    vectors = _vectors()
    positive = vectors["positives"][2]
    plan = positive["plan"]
    if change == "at_sign":
        plan["workload"]["description"] += " for someone" + "@" + "example.org"
    elif change == "at_sign_key":
        positive["intent"] = "a run" + "@" + "noon"
    elif change == "project":
        plan["project"]["id"] = "qual-run-0001"
    elif change == "repository":
        plan["workload"]["repository"] = "workload-repo"
    elif change == "image_project":
        plan["machines"][0]["image"]["project"] = "images"
    elif change == "approval":
        positive["lease"]["approval"]["reference"] = "OA-0001"
    elif change == "project_twice":
        plan["purpose"]["summary"] += " in " + plan["project"]["id"]
    else:
        positive["lease"]["leaseId"] = positive["teardown"]["leaseId"] = "LE-20261019-" + plan["project"]["id"]
    _repin(monkeypatch, vectors, 2)
    with pytest.raises(ValueError, match="positive P2 carries only invented identifiers"):
        VALIDATE()


@pytest.mark.parametrize("change, message", [
    ("top_extra", "a closed vectors file"),
    ("top_schema", "a closed vectors file"),
    ("fourth_positive", "a closed vectors file"),
    ("negative_key", "a closed negative vector"),
    ("negative_positive", "a closed negative vector"),
    ("negative_target", "a closed negative vector"),
    ("negative_no_ops", "a closed negative vector"),
    ("negative_no_refusal", "a closed negative vector"),
    ("negative_dropped", "the negatives' identifiers and targets are restated"),
    ("negative_retargeted", "the negatives' identifiers and targets are restated"),
    ("negative_renamed", "the negatives' identifiers and targets are restated"),
    ("top_no_parse", "a closed vectors file"),
    ("parse_key", "a closed parse negative"),
    ("parse_empty_raw", "a closed parse negative"),
    ("parse_dropped", "the parse negatives' identifiers are restated"),
    ("parse_renamed", "the parse negatives' identifiers are restated"),
])
def test_the_vectors_file_and_its_negatives_are_restated(monkeypatch, change, message):
    vectors = _vectors()
    negatives = vectors["negatives"]
    if change == "top_extra":
        vectors["notes"] = []
    elif change == "top_schema":
        vectors["schemaVersion"] = "planeon.internal.lab-run-plan-vectors/v2"
    elif change == "fourth_positive":
        vectors["positives"].append(copy.deepcopy(vectors["positives"][0]))
    elif change == "negative_key":
        negatives[0]["note"] = "x"
    elif change == "negative_positive":
        negatives[0]["positive"] = 3
    elif change == "negative_target":
        negatives[0]["target"] = "budget"
    elif change == "negative_no_ops":
        negatives[0]["ops"] = []
    elif change == "negative_no_refusal":
        negatives[0]["refusal"] = ""
    elif change == "negative_dropped":
        negatives.pop()
    elif change == "negative_retargeted":
        next(row for row in negatives if row["target"] == "lease")["target"] = "plan"
    elif change == "negative_renamed":
        negatives[0]["id"] = "N99"
    elif change == "top_no_parse":
        del vectors["parseNegatives"]
    elif change == "parse_key":
        vectors["parseNegatives"][0]["note"] = "x"
    elif change == "parse_empty_raw":
        vectors["parseNegatives"][0]["raw"] = ""
    elif change == "parse_dropped":
        vectors["parseNegatives"].pop()
    else:
        vectors["parseNegatives"][0]["id"] = "S99"
    _rebind(monkeypatch, {profile.VECTORS_PATH: _dump(vectors)})
    with pytest.raises(ValueError, match=re.escape(message)):
        VALIDATE()


def test_the_restated_negatives_cover_every_document():
    vectors = _vectors()
    assert tuple(row["id"] for row in vectors["negatives"]) == profile.NEGATIVE_IDS
    assert len(profile.NEGATIVE_IDS) == sum(profile.NEGATIVE_COUNTS.values()) == 99
    assert {row["target"] for row in vectors["negatives"]} == set(profile.NEGATIVE_COUNTS)
    assert any("@" in json.dumps(row["ops"]) for row in vectors["negatives"])
    assert tuple(row["id"] for row in vectors["parseNegatives"]) == profile.PARSE_IDS and len(profile.PARSE_IDS) == 9
    assert profile.CHECKER_COUNTS == {"positives": 3, "plan": 68, "lease": 11, "teardown": 20, "parse": 9}


# The checker ---------------------------------------------------------------------------------------------------------

def _checker_with(monkeypatch, old, new):
    raw = profile.reviewed_bytes(profile.CHECKER)
    assert raw.count(old) == 1
    _rebind(monkeypatch, {profile.CHECKER: raw.replace(old, new)})


@pytest.mark.parametrize("old, new", [
    (b"import math\n", b"import math\nimport os\n"),
    (b"import math\n", b"import math\nimport urllib.request\n"),
    (b"import math\n", b"import math\nfrom subprocess import run\n"),
    (b"def _load(path: str) -> Any:\n", b"def _keep(path: str) -> None:\n    Path(path).write_text('x')\n\n\n"
                                         b"def _load(path: str) -> Any:\n"),
    (b"def _load(path: str) -> Any:\n", b"def _keep(path: str) -> None:\n    open(path, 'w')\n\n\n"
                                         b"def _load(path: str) -> Any:\n"),
    (b"def _load(path: str) -> Any:\n", b"def _keep(path: str) -> None:\n    Path(path).unlink()\n\n\n"
                                         b"def _load(path: str) -> Any:\n"),
    (b"def _load(path: str) -> Any:\n", b"def _keep(text: str) -> None:\n    eval(text)\n\n\n"
                                         b"def _load(path: str) -> Any:\n"),
])
def test_the_checker_imports_only_the_standard_library_and_writes_nothing(monkeypatch, old, new):
    _checker_with(monkeypatch, old, new)
    with pytest.raises(ValueError, match="the checker imports only the standard library and names no file writer"):
        VALIDATE()


@pytest.mark.parametrize("old, new", [
    (b'"BUCKETS", "SERVICE_ACCOUNTS", ', b'"SERVICE_ACCOUNTS", '),
    (b'ALWAYS_KEPT = {"PROJECT", "OBSERVER_IDENTITY"}', b'ALWAYS_KEPT = {"PROJECT"}'),
    (b'VECTORS_PATH = CONTRACT_DIR + "vectors.json"', b'VECTORS_PATH = CONTRACT_DIR + "vectors-v2.json"'),
    (b'"exclusiveMinimum"}', b'"exclusiveMinimum", "format"}'),
    (b'"BUCKETS": ("roles/iam.securityReviewer",)', b'"BUCKETS": ("roles/compute.viewer",)'),
    (b're.compile(r"github_pat_"), ', b''),
])
def test_the_checker_holds_the_restated_constants(monkeypatch, old, new):
    _checker_with(monkeypatch, old, new)
    with pytest.raises(ValueError, match="the checker holds the restated constants"):
        VALIDATE()


def test_the_checker_is_executed_from_its_reviewed_bytes(monkeypatch):
    """Bytes served for the checker are what runs: a served replay that counts differently is refused, so nothing is
    imported from disk."""
    _checker_with(monkeypatch, b'    counts = {"positives": len(positives), "plan": 0, "lease": 0, "teardown": 0, "parse": 0}\n',
                  b'    counts = {"positives": len(positives), "plan": 1, "lease": 0, "teardown": 0, "parse": 0}\n')
    with pytest.raises(ValueError, match="the checker accepts each positive and refuses each negative as recorded"):
        VALIDATE()


def test_a_changed_recorded_refusal_fails_the_replay(monkeypatch):
    vectors = _vectors()
    vectors["negatives"][-1]["refusal"] += " (changed)"
    _rebind(monkeypatch, {profile.VECTORS_PATH: _dump(vectors)})
    with pytest.raises(ValueError, match="the checker accepts each positive and refuses each negative as recorded"):
        VALIDATE()


def test_a_checker_that_accepts_a_negative_fails_the_replay(monkeypatch):
    _checker_with(monkeypatch, b'require((expiry - start).total_seconds() <= plan["maxDurationHours"] * 3600, ',
                  b'require(True or (expiry - start).total_seconds() <= plan["maxDurationHours"] * 3600, ')
    with pytest.raises(ValueError, match="the checker accepts each positive and refuses each negative as recorded"):
        VALIDATE()


def test_a_free_text_negative_must_trip_exactly_one_shape(monkeypatch):
    vectors = _vectors()
    row = next(row for row in vectors["negatives"] if row["id"] == "N46")
    row["ops"][0]["value"] += " AKIAEXAMPLE0000"
    _rebind(monkeypatch, {profile.VECTORS_PATH: _dump(vectors)})
    with pytest.raises(ValueError, match="each free-text negative trips exactly one forbidden shape: N46"):
        VALIDATE()


def test_every_forbidden_shape_has_a_negative_of_its_own(monkeypatch):
    vectors = _vectors()
    row = next(row for row in vectors["negatives"] if row["id"] == "N49")
    row["ops"][0]["value"] = "contact the run owner at ops" + "@" + "example.com"
    _rebind(monkeypatch, {profile.VECTORS_PATH: _dump(vectors)})
    with pytest.raises(ValueError, match="every forbidden shape has a negative of its own"):
        VALIDATE()


def test_a_checker_that_refuses_a_schema_fails(monkeypatch):
    _checker_with(monkeypatch, b"def check_schema(schema: Any, where: str = \"$\") -> None:\n",
                  b"def check_schema(schema: Any, where: str = \"$\") -> None:\n    require(False, \"refused\")\n")
    with pytest.raises(ValueError, match="the checker accepts the schema: " + re.escape(profile.PLAN_SCHEMA)):
        VALIDATE()


def test_the_checker_computes_the_restated_plan_sha256(monkeypatch):
    _checker_with(monkeypatch, b"    return hashlib.sha256(canonical(plan)).hexdigest()\n",
                  b"    return hashlib.sha256(canonical(plan) + b\" \").hexdigest()\n")
    with pytest.raises(ValueError, match="the checker computes each positive's restated plan sha256"):
        VALIDATE()


def test_the_checker_replays_every_vector_as_recorded():
    checker = profile._era_model(profile.CHECKER, "_test_lab_run_plan")
    loaded = {kind: checker.strict(profile.reviewed_bytes(path)) for kind, path in profile.SCHEMAS.items()}
    vectors = checker.strict(profile.reviewed_bytes(profile.VECTORS_PATH))
    assert checker.replay(vectors, loaded) == profile.CHECKER_COUNTS
    for row in vectors["negatives"]:
        assert row["refusal"] and not row["refusal"].startswith("negative vector")


# Projection and reads ------------------------------------------------------------------------------------------------

def test_a_later_successor_leaves_this_era_valid_through_projection(monkeypatch):
    original, reviewed = profile.regular_bytes, profile.reviewed_bytes
    paths = (profile.README_PATH, profile.VECTORS_PATH, profile.CHECKER)
    era = {path: reviewed(path) for path in paths}
    later = {profile.README_PATH: era[profile.README_PATH] + b"\nA later note.\n",
             profile.VECTORS_PATH: era[profile.VECTORS_PATH].replace(b'"DATA_CHECK_ONLY"', b'"DATA_CHECK_LATER"', 1),
             profile.CHECKER: era[profile.CHECKER] + b"\nraise ValueError('later module')\n"}
    monkeypatch.setattr(profile, "regular_bytes", lambda path: later.get(path) or original(path))
    with pytest.raises(ValueError):
        VALIDATE()
    monkeypatch.setattr(profile, "reviewed_bytes", lambda path: era[path] if path in later else reviewed(path))
    assert VALIDATE() is None
    # A later file in the contract directory is projected away through reviewed_tree.
    tree = profile.reviewed_tree(profile.CONTRACT_DIR)
    monkeypatch.setattr(profile, "reviewed_tree", lambda directory: {**tree, profile.CONTRACT_DIR + "later.json": 0o100644})
    with pytest.raises(ValueError, match="holds exactly its files"):
        VALIDATE()
    monkeypatch.setattr(profile, "reviewed_tree", lambda directory: tree)
    assert VALIDATE() is None


def test_reviewed_bytes_is_the_only_semantic_read():
    tree = ast.parse(profile.regular_bytes(profile.VALIDATOR_PATH))
    names = {"_verified", "_json", "_holds", "_bound", "_era_model", "local_paths", "_strings", "validate_contract_files",
             "validate_status", "validate_readme", "_closed", "validate_schemas", "_cost_holds", "validate_vectors",
             "validate_checker", "validate_lab_run_plan"}
    seen = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            seen.add(node.name)
            used = {name.id for name in ast.walk(node) if isinstance(name, ast.Name)}
            attributes = {attribute.attr for attribute in ast.walk(node) if isinstance(attribute, ast.Attribute)}
            assert not used & {"regular_bytes", "open"}, node.name
            assert not attributes & {"read_bytes", "read_text", "open", "lstat", "stat", "iterdir", "glob", "rglob"}, node.name
    assert seen == names


def test_the_check_reads_no_unverified_byte(monkeypatch):
    """Every byte the check uses comes through reviewed_bytes: with those served from memory, the authority the generic
    layer checked served as checked, and every other file read refused, the whole check still holds."""
    paths = set(profile.ERA_SHA256) | set(profile._PROJECTION_RULES)
    served = {path: profile.reviewed_bytes(path) for path in paths}
    record = profile.authority()
    monkeypatch.setattr(profile, "reviewed_bytes", lambda target: served[target])
    monkeypatch.setattr(profile, "authority", lambda: record)

    def refused(*args, **kwargs):
        raise AssertionError("unverified read: %r" % (args[:1],))
    monkeypatch.setattr(Path, "read_bytes", refused)
    monkeypatch.setattr(Path, "read_text", refused)
    monkeypatch.setattr(Path, "open", refused)
    import builtins
    monkeypatch.setattr(builtins, "open", refused)
    assert VALIDATE() is None


def _line_hunks(after, before):
    import difflib
    current, previous = after.splitlines(keepends=True), before.splitlines(keepends=True)
    offsets = [0]
    for line in current:
        offsets.append(offsets[-1] + len(line))
    return tuple((offsets[a], b"".join(current[a:b]), b"".join(previous[c:d]))
                 for tag, a, b, c, d in difflib.SequenceMatcher(None, current, previous, autojunk=False).get_opcodes()
                 if tag != "equal")


def test_whole_line_hunks_are_refused_where_canonical_ones_differ(monkeypatch):
    rules = dict(profile._PROJECTION_RULES)
    path = next(path for path, rule in rules.items()
                if _line_hunks(profile.reviewed_bytes(path), profile._undo_this_layer(path, profile.reviewed_bytes(path)))
                != rule["reverseHunks"])
    after = profile.reviewed_bytes(path)
    before = profile._undo_this_layer(path, after)
    line = _line_hunks(after, before)
    assert profile._inverse(after, line) == before
    rules[path] = MappingProxyType(dict(rules[path], reverseHunks=line))
    monkeypatch.setattr(profile, "_PROJECTION_RULES", MappingProxyType(rules))
    with pytest.raises(ValueError, match=re.escape("canonical byte-minimal inverse hunks: " + path)):
        profile.validate_canonical_hunks()


def test_every_recorded_hunk_is_canonical_and_reconstructs():
    for path, rule in profile._PROJECTION_RULES.items():
        after = profile.reviewed_bytes(path)
        before = profile._undo_this_layer(path, after)
        hunks = profile.canonical_hunks(after, before)
        assert hunks == rule["reverseHunks"] and profile._inverse(after, hunks) == before
        prior_end = -1
        for at, removed, inserted in hunks:
            assert at > prior_end and removed != inserted
            assert not (removed and inserted and (removed[0] == inserted[0] or removed[-1] == inserted[-1]))
            prior_end = at + len(removed)
