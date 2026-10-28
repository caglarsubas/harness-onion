"""Exact source lineage for MET-LIVE-003; the neutral Linux probe interface (Q-PK-6) as harness-onion data (the four v1/ handoff files byte-identical, the closed binding record with LPK-0's NEUTRAL_INTERFACE_CONTRACT placeholder bound, the reference model and its vectors) with its adoption records and D5a oracle: the head keeps the full fan-in (8 own and 73 predecessor routes, every catalog walk and round trip, the full payload loop), and the semantic check (the freeze, the files added, the adoption, the handoff bytes, the source and reviews, A8's forward pin, the reference model and the vectors' replay, the unchanged registry, the derived gate check, and the canonical hunks) has a failing case for every refusal, each on plain data."""
import ast
import json
from copy import deepcopy
import os
import re
import stat
from pathlib import Path
from types import MappingProxyType

import pytest

from scripts import validate_linux_probe_interface as profile
from scripts import validate_linux_probe_kit_gate as lkg
from scripts import validate_probe_kit_scope as pks
from scripts import validate_review_record as rrv
from scripts import validate_policy_observation_digests as pod
from scripts import validate_evolution_surface as evs
from scripts import validate_edge_record_v9 as e9
from scripts import validate_chain_compaction as ccomp
from scripts import validate_i06_backend_profile_v4 as i6v4
from scripts import validate_diagnostic_caps as dcap
from scripts import validate_native_profile_v5 as np5
from scripts import validate_lab_run_plan as lrp
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
from scripts.validate_policy_observation import validate_messages
from scripts.validate_proxy_contract import validate_profile


def packets():
    return {path.stem: safe_load(path.read_bytes())
            for path in (profile.ROOT / "task-packets").glob("*.yaml")}


def layer_packets():
    # The newer MET-LIVE-004 layer is projected away before this layer's payload checks.
    return profile.successor.historical_catalog(packets())


def changed_test():
    return next(path for path in profile._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert profile.validate() is None
    current = packets()
    accepted = profile.historical_catalog(current)
    assert len(current) == 269 and len(accepted) == 261
    assert set(accepted) == set(current) - {profile.NEW_PACKET, profile.successor.NEW_PACKET,
                                            profile.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET}
    assert len(lkg.historical_catalog(current)) == 260
    assert len(pks.historical_catalog(current)) == 259
    assert len(rrv.historical_catalog(current)) == 258
    assert len(pod.historical_catalog(current)) == 257
    assert len(evs.historical_catalog(current)) == 256
    assert len(e9.historical_catalog(current)) == 255
    assert len(ccomp.historical_catalog(current)) == 254
    assert len(i6v4.historical_catalog(current)) == 253
    assert len(dcap.historical_catalog(current)) == 252
    assert len(np5.historical_catalog(current)) == 251
    assert len(lrp.historical_catalog(current)) == 250
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
    lkg_before = lkg.historical_bytes(path, current)
    assert lkg.current_test_bytes(lkg_before) == current
    pks_before = pks.historical_bytes(path, current)
    assert pks.current_test_bytes(pks_before) == current
    rrv_before = rrv.historical_bytes(path, current)
    assert rrv.current_test_bytes(rrv_before) == current
    pod_before = pod.historical_bytes(path, current)
    assert pod.current_test_bytes(pod_before) == current
    evs_before = evs.historical_bytes(path, current)
    assert evs.current_test_bytes(evs_before) == current
    e9_before = e9.historical_bytes(path, current)
    assert e9.current_test_bytes(e9_before) == current
    ccomp_before = ccomp.historical_bytes(path, current)
    assert ccomp.current_test_bytes(ccomp_before) == current
    i6v4_before = i6v4.historical_bytes(path, current)
    assert i6v4.current_test_bytes(i6v4_before) == current
    dcap_before = dcap.historical_bytes(path, current)
    assert dcap.current_test_bytes(dcap_before) == current
    np5_before = np5.historical_bytes(path, current)
    assert np5.current_test_bytes(np5_before) == current
    lrp_before = lrp.historical_bytes(path, current)
    assert lrp.current_test_bytes(lrp_before) == current
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


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "lkg_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = profile.historical_bytes(path, raw) if route in ("current_test", "old_bytes") else None
    current_packets = packets() if route == "catalog" else None
    layer = layer_packets() if route == "payloads" else None
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
    old_lkg = lkg.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "lkg_old" else None
    old_pks = pks.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "pks_old" else None
    old_rrv = rrv.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "rrv_old" else None
    old_pod = pod.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "pod_old" else None
    old_evs = evs.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "evs_old" else None
    old_e9 = e9.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "e9_old" else None
    old_ccomp = ccomp.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "ccomp_old" else None
    old_i6v4 = i6v4.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "i6v4_old" else None
    old_dcap = dcap.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "dcap_old" else None
    old_np5 = np5.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "np5_old" else None
    old_lrp = lrp.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "lrp_old" else None
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
        "lkg_old": lambda: lkg.historical_bytes(roadmap.MASTER_PATH, old_lkg),
        "pks_old": lambda: pks.historical_bytes(roadmap.MASTER_PATH, old_pks),
        "rrv_old": lambda: rrv.historical_bytes(roadmap.MASTER_PATH, old_rrv),
        "pod_old": lambda: pod.historical_bytes(roadmap.MASTER_PATH, old_pod),
        "evs_old": lambda: evs.historical_bytes(roadmap.MASTER_PATH, old_evs),
        "e9_old": lambda: e9.historical_bytes(roadmap.MASTER_PATH, old_e9),
        "ccomp_old": lambda: ccomp.historical_bytes(roadmap.MASTER_PATH, old_ccomp),
        "i6v4_old": lambda: i6v4.historical_bytes(roadmap.MASTER_PATH, old_i6v4),
        "dcap_old": lambda: dcap.historical_bytes(roadmap.MASTER_PATH, old_dcap),
        "np5_old": lambda: np5.historical_bytes(roadmap.MASTER_PATH, old_np5),
        "lrp_old": lambda: lrp.historical_bytes(roadmap.MASTER_PATH, old_lrp),
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
    with pytest.raises(ValueError, match="linux probe interface history authority digest"):
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
    assert len(profile.historical_catalog(current)) == 261


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
    assert len(profile.historical_catalog(current)) == 261
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
    assert len(rules) == 262 and len(parsed) == 261
    assert profile._packet_rules() is rules and len(parsed) == 261
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
    with pytest.raises(ValueError, match="linux probe interface history authority digest"):
        profile.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = layer_packets()
    profile.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "linux-probe-interface-authority.json").write_bytes(
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
    # The newer MET-LIVE-004 layer refuses a mutated validator before this layer.
    with pytest.raises(ValueError, match="unreviewed current source: scripts/validate_linux_probe_interface.py"):
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
            assert all("validate_" not in alias.name or alias.name == "validate_linux_probe_kit_admission"
                       for alias in node.names)


def _count_authority_reads(monkeypatch):
    counts = {}
    for module in (profile.successor, profile, lkg, pks, rrv, pod, evs, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner):
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
    expected = {module.__name__: 1 for module in (profile.successor, profile, lkg, pks, rrv, pod, evs, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner)}
    if route == "current_test":
        # The forward route reads this layer's newest bytes and then projects them forward once more.
        assert all(counts[name] >= 1 for name in expected) and set(counts) == set(expected)
    else:
        assert counts == expected


# MET-LIVE-003 (LINUX-PROBE-INTERFACE): this era's check, and a failing case for every check. Every mutant below is
# applied to plain data handed to the layer's pure checks: nothing in the layer or the library is patched or swapped. The
# mutants are built by the pure helpers _<area>_mutant(change), one change name per mutant. The reference model, the
# evolution surface model and replay.py are executed from this era's verified bytes through the layer's era loader. This
# test also reaches what the layer does not, since the names are not attribute names the frozen allow-list admits: the
# model's own valid, HANDOFF and refusal table R, and replay.py's apply, files_for, reader and run; the layer's restated
# replay must agree with replay.py's, vector by vector. The source commit is never resolved.

VALIDATE = profile.validate_linux_probe_interface
# Tamper values name paths that already exist and that this packet does not carry in the tampered place.
OTHER_PATH = "scripts/validate_linux_probe_kit_gate.py"
_CACHE = {}


def _models():
    if "models" not in _CACHE:
        _CACHE["models"] = profile.era_models()
    return _CACHE["models"]


def _replay_py():
    """replay.py, executed from this era's verified bytes (it reads nothing when it is not run as a script)."""
    if "replay" not in _CACHE:
        _CACHE["replay"] = profile._era_model(profile.REPLAY_PATH, "_met_live_003_replay")
    return _CACHE["replay"]


def _status():
    return json.loads(profile._verified(profile.STATUS_PATH))


def _binding():
    return json.loads(profile._verified(profile.BINDING_PATH))


def _vectors():
    return json.loads(profile._verified(profile.VECTORS_PATH))


def _v1():
    return {name: profile._verified(profile.V1_DIR + name) for name in profile.V1_NAMES}


def _lpk0():
    return profile._verified(profile.LPK0_RECORD)


def _changed():
    record = profile.authority()
    return sorted(set(record["changedFiles"]) | set(record["newFiles"])
                  | {profile.AUTHORITY_PATH, profile.VALIDATOR_PATH, profile.PACKET_PATH})


def _gate():
    return _models()[1].check(json.loads(profile._verified(profile.SURFACE_RECORD)))["gateMaterial"]


def _flip(text):
    """A different lowercase hex digest of the same length."""
    return text[:-1] + ("0" if text[-1] != "0" else "1")


def test_the_contract_holds_for_this_era():
    assert VALIDATE() is None


def test_the_era_holds_the_added_files_lpk0s_record_the_registry_and_the_surface():
    assert set(profile.ERA_SHA256) == set(profile.NEW_FILES) | {profile.LPK0_RECORD, profile.REGISTRY_PATH,
                                                                profile.PACKET_BRIEF, profile.SURFACE_RECORD,
                                                                profile.SURFACE_MODEL}
    assert len(profile.ERA_SHA256) == 19 and len(profile.NEW_FILES) == 14 and len(set(profile.NEW_FILES)) == 14
    assert set(profile.CONTRACT_FILES) == set(profile.ADOPTED_SUBJECT) and len(profile.CONTRACT_FILES) == 9
    assert profile.V1_FILES == tuple("architecture/linux-probe-interface/v1/" + name for name in (
        "MANIFEST.json", "README.md", "probe-interface.json", "probe-interface.schema.json"))
    for path, expected in profile.ADOPTED_SUBJECT.items():
        assert profile.ERA_SHA256[path] == expected
    assert profile.ERA_SHA256[profile.ORACLE_TEST] == profile.ORACLE_SHA256
    assert profile.ERA_SHA256[profile.ORACLE_IDENTITY_PATH] == profile.IDENTITY_SHA256
    assert profile.ERA_SHA256[profile.REGISTRY_PATH] == profile.REGISTRY_SHA256
    assert profile.ERA_SHA256[profile.LPK0_RECORD] == profile.STATUS_PIN["sha256"] == (
        "3de2d73e0413388ba286899cdd364c876dfbd869510c88537da8b1c91726ef8b")
    assert [row["record"] for row in _status()["reviews"]] == list(profile.HISTORY_RECORDS)
    assert [row["brief"] for row in _status()["reviews"]] == list(profile.HISTORY_BRIEFS)
    for path, expected in profile.ERA_SHA256.items():
        assert profile.digest(profile.reviewed_bytes(path)) == expected


@pytest.mark.parametrize("path", sorted(profile.ERA_SHA256))
def test_every_era_file_is_bound_by_digest(path):
    raw = profile._verified(path)
    assert profile._era_bytes(path, raw) == raw
    for changed in (raw + b" ", bytearray(raw)):
        with pytest.raises(ValueError, match=re.escape("unreviewed LINUX-PROBE-INTERFACE source: " + path)):
            profile._era_bytes(path, changed)


def test_a_path_outside_the_era_is_refused_before_it_is_read():
    for path in (profile.CONTRACT_DIR + "/notes.md", profile.V1_DIR + "extra.json", "architecture/probe-kit-scope/README.md",
                 "architecture/review-briefs/REVIEW_BRIEF_CONTRACT.md", OTHER_PATH, profile.VALIDATOR_PATH,
                 profile.HEAD_TEST, profile.LIVING_CATALOGS[0], None):
        with pytest.raises(ValueError, match="MET-LIVE-003 reviewed bytes are bound: "):
            profile._verified(path)
        with pytest.raises(ValueError, match="MET-LIVE-003 reviewed bytes are bound: "):
            profile._era_bytes(path, b"")


def test_the_era_models_are_executed_from_verified_bytes():
    model, surface = _models()
    assert model.__name__ == "_met_live_003_linux_probe_interface"
    assert surface.__name__ == "_met_live_003_evolution_surface"
    assert model.__file__ == str(profile.ROOT / profile.MODEL_PATH)
    assert surface.__file__ == str(profile.ROOT / profile.SURFACE_MODEL)
    assert _replay_py().__file__ == str(profile.ROOT / profile.REPLAY_PATH)


# The freeze and the files this packet adds -----------------------------------------------------------------------------

FREEZE = "this packet edits only chain validators, tests and the three living catalogs: "


@pytest.mark.parametrize("path", ["scripts/linux_probe_interface.py", "scripts/evolution_surface.py",
                                  "scripts/review_record.py", "scripts/chain_identity.py", "scripts/probe_kit_scope.py",
                                  "architecture/probe-kit-scope/amendment.json", "architecture/review-record/briefs.json",
                                  "architecture/review-briefs/REVIEW_BRIEF_PACKET.md",
                                  "architecture/evolution-surface/evolution-surface.json",
                                  "architecture/linux-probe-interface/binding.json",
                                  "architecture/linux-probe-interface/v1/README.md", "docs/DEVELOPMENT_STATUS.md",
                                  "docs/linux-probe-kit/README.md", "linux-probe-kit/README.md", "tests/conftest.py",
                                  "conftest.py", "scripts/validate_x/y.py", "scripts/validate_x.txt",
                                  "ci/linux-runner/runner.py", "pyproject.toml", None])
def test_the_freeze_refuses_every_other_change(path):
    changed = list(profile._PROJECTION_RULES)
    profile.check_freeze(changed)
    with pytest.raises(ValueError, match=re.escape(FREEZE)):
        profile.check_freeze(changed + [path])


def _added_mutant(change):
    added = list(profile.NEW_FILES) + [profile.HEAD_TEST]
    if change == "missing":
        added.remove(profile.STATUS_PATH)
    elif change == "extra":
        added.append(profile.CONTRACT_DIR + "/review-round1.json")
    elif change == "duplicate":
        added.append(profile.MODEL_PATH)
    elif change == "no_head_test":
        added.remove(profile.HEAD_TEST)
    elif change == "v2":
        added.append(profile.CONTRACT_DIR + "/v2/MANIFEST.json")
    else:
        added = tuple(added)
    return added


@pytest.mark.parametrize("change", ["missing", "extra", "duplicate", "no_head_test", "v2", "not_list"])
def test_the_packet_adds_exactly_its_files_each_once(change):
    profile.check_new_files(list(profile.NEW_FILES) + [profile.HEAD_TEST])
    profile.check_new_files(list(profile.authority()["newFiles"]))
    with pytest.raises(ValueError, match="this packet adds exactly its contract files, adoption records, oracle test and "
                                         "layer test, each once"):
        profile.check_new_files(_added_mutant(change))


@pytest.mark.parametrize("path", profile.NEW_FILES)
def test_an_added_file_is_a_regular_file_of_mode_100644_without_a_local_path(path):
    raw, mode = profile._verified(path), profile.reviewed_mode(path)
    profile.check_added_file(path, mode, raw)
    for changed in (stat.S_IFREG | 0o755, stat.S_IFLNK | 0o777, None):
        with pytest.raises(ValueError, match=re.escape("a file this packet adds is a regular file of git mode 100644: "
                                                       + path)):
            profile.check_added_file(path, changed, raw)
    for marker in (b"/" + b"Users/x", b"/" + b"private/tmp/x", b"~/.local" + b"/state/x", b"/" + b"USERS/1"):
        with pytest.raises(ValueError, match=re.escape("no absolute local path in a file this packet adds: " + path)):
            profile.check_added_file(path, mode, raw + marker)
    profile.check_added_file(path, mode, raw + b" /" + b"users, /" + b"private, .local" + b"/state, e-mail pattern")


# The adoption ----------------------------------------------------------------------------------------------------------

STATUS_CHANGES = ["schema", "work_item", "packet", "slot", "slot_text", "slot_float", "status", "base", "design",
                  "reviewers", "note", "pin_digest", "pin_base", "oracle", "slips", "non_claim", "extra_key",
                  "missing_key", "key_order"]


def _status_mutant(change):
    status = _status()
    if change == "schema":
        status["schemaVersion"] = "planeon.internal.linux-probe-interface-status/v2"
    elif change == "work_item":
        status["workItem"] = "LINUX-PROBE-KIT-001"
    elif change == "packet":
        status["packet"] = "MET-LIVE-004"
    elif change == "slot":
        status["slot"] = 263
    elif change == "slot_text":
        status["slot"] = "262"
    elif change == "slot_float":
        status["slot"] = 262.0
    elif change == "status":
        status["status"] = "ADOPTED_CONTRACT_CANDIDATE"
    elif change == "base":
        status["baseMain"] = "b821ed656a9311529d23e443c8d903a17ad309d9"
    elif change == "design":
        status["design"]["sha256"] = _flip(status["design"]["sha256"])
    elif change == "reviewers":
        status["independentReviewers"] = "the author"
    elif change == "note":
        status["reviewHistoryNote"] += " They carry merge authority."
    elif change == "pin_digest":
        status["predecessorPin"]["sha256"] = _flip(status["predecessorPin"]["sha256"])
    elif change == "pin_base":
        status["predecessorPin"]["atBase"] = "b821ed656a9311529d23e443c8d903a17ad309d9"
    elif change == "oracle":
        status["oracle"]["result"] = "85/86"
    elif change == "slips":
        status["slips"].pop()
    elif change == "non_claim":
        status["nonClaims"][0] = status["nonClaims"][0].replace("FORM_ONLY", "ACCEPTED")
    elif change == "extra_key":
        status["merged"] = True
    elif change == "missing_key":
        del status["nonClaims"]
    else:
        status = dict(reversed(list(status.items())))
    return status


@pytest.mark.parametrize("change", STATUS_CHANGES)
def test_the_status_is_closed_and_records_the_adoption(change):
    profile.check_status(_status())
    with pytest.raises(ValueError, match="adopted LINUX-PROBE-INTERFACE status"):
        profile.check_status(_status_mutant(change))


def _adoptions_mutant(change):
    adoptions = deepcopy(_status()["adoptions"])
    if change == "drop_c6":
        adoptions.pop()
    elif change == "drop_c2":
        adoptions.pop(0)
    elif change == "reorder":
        adoptions[0], adoptions[1] = adoptions[1], adoptions[0]
    elif change == "check_digest":
        adoptions[-1]["adoptionCheckSha256"] = _flip(adoptions[-1]["adoptionCheckSha256"])
    elif change == "ruling":
        adoptions[2]["ruling"] = "MON-LIVE003-ADOPT-C5"
    elif change == "extra_key":
        adoptions[0]["note"] = "x"
    elif change == "key_order":
        adoptions[0] = dict(reversed(list(adoptions[0].items())))
    else:
        adoptions.append(dict(adoptions[-1], candidate="c7"))
    return adoptions


@pytest.mark.parametrize("change", ["drop_c6", "drop_c2", "reorder", "check_digest", "ruling", "extra_key", "key_order",
                                    "c7"])
def test_the_adoptions_run_c2_to_c6_with_their_check_digests(change):
    profile.check_adoptions(_status()["adoptions"])
    with pytest.raises(ValueError, match="the adoptions run c2 to c6 with their rulings and ADOPTION_CHECK digests"):
        profile.check_adoptions(_adoptions_mutant(change))


def _files():
    return {path: profile._verified(path) for path in profile.ADOPTED_SUBJECT}


def _subject_mutant(change):
    subject = dict(_status()["adoptedSubject"])
    if change == "digest":
        subject[profile.README_PATH] = _flip(subject[profile.README_PATH])
    elif change == "missing":
        del subject[profile.REPLAY_PATH]
    elif change == "extra":
        subject[profile.STATUS_PATH] = "0" * 64
    else:
        subject = dict(reversed(list(subject.items())))
    return subject


@pytest.mark.parametrize("change", ["digest", "missing", "extra", "order"])
def test_status_names_the_adopted_subject_by_digest(change):
    profile.check_subject(_status()["adoptedSubject"], _files())
    with pytest.raises(ValueError, match="status.json names the adopted subject by digest"):
        profile.check_subject(_subject_mutant(change), _files())


@pytest.mark.parametrize("path", list(profile.ADOPTED_SUBJECT))
def test_the_adopted_files_are_the_adopted_subjects_bytes(path):
    files = _files()
    for changed in (files[path] + b"\n", None):
        with pytest.raises(ValueError, match=re.escape("the adopted files are the adopted subject's bytes: " + path)):
            profile.check_subject(_status()["adoptedSubject"], {**files, path: changed})


def _lists_mutant(change):
    status = _status()
    if change == "review_missing":
        status["reviews"].pop()
    elif change == "redaction_missing":
        status["briefRedactions"].pop()
    elif change == "redaction_extra":
        status["briefRedactions"].append(status["briefRedactions"][0])
    else:
        status["reviews"] = tuple(status["reviews"])
    return status


@pytest.mark.parametrize("change", ["review_missing", "redaction_missing", "redaction_extra", "reviews_not_list"])
def test_every_review_and_redaction_is_recorded(change):
    profile.check_review_lists(_status())
    with pytest.raises(ValueError, match="every review and brief redaction is recorded"):
        profile.check_review_lists(_lists_mutant(change))


def _review_parts(number):
    return (_status()["reviews"][number - 1], profile._verified(profile.HISTORY_RECORDS[number - 1]),
            profile._verified(profile.HISTORY_BRIEFS[number - 1]))


def _review_mutant(number, change):
    row, record, brief = _review_parts(number)
    row = deepcopy(row)
    if change == "record_bytes":
        record = record + b" "
    elif change == "brief_bytes":
        brief = brief + b"\n"
    elif change == "row_digest":
        row["recordSha256"] = _flip(row["recordSha256"])
    elif change == "row_verdict":
        row["verdict"] = "PASS_FOR_ADOPTION"
    elif change == "row_path":
        row["record"] = profile.HISTORY_BRIEFS[number - 1]
    elif change == "key_order":
        row = dict(reversed(list(row.items())))
    elif change == "number":
        number = number + 1
    else:
        record = None
    return number, row, record, brief


@pytest.mark.parametrize("change", ["record_bytes", "brief_bytes", "row_digest", "row_verdict", "row_path", "key_order",
                                    "number", "record_not_bytes"])
def test_the_light_review_is_bound_to_its_published_record_and_brief(change):
    profile.check_review(1, *_review_parts(1))
    record = json.loads(profile._verified(profile.HISTORY_RECORDS[0]))
    assert record["verdict"] == "CHANGES_REQUIRED" and record["brief"]["sha256"] == profile.REVIEW_ROWS[0][
        "briefReviewedSha256"]
    with pytest.raises(ValueError, match=re.escape("a review is bound to its published record and brief: review ")):
        profile.check_review(*_review_mutant(1, change))


def _redaction_mutant(number, change):
    status = _status()
    row, redaction = status["reviews"][number - 1], deepcopy(status["briefRedactions"][number - 1])
    brief = profile._verified(profile.HISTORY_BRIEFS[number - 1])
    if change == "count":
        redaction["substitutions"][0]["count"] = 5
    elif change == "to":
        redaction["substitutions"][1]["to"] = "<tmp>/"
    elif change == "from_digest":
        redaction["substitutions"][0]["fromSha256"] = _flip(redaction["substitutions"][0]["fromSha256"])
    elif change == "published":
        redaction["publishedSha256"] = _flip(redaction["publishedSha256"])
    elif change == "reviewed":
        redaction["reviewedSha256"] = _flip(redaction["reviewedSha256"])
    elif change == "brief_path":
        redaction["brief"] = profile.HISTORY_RECORDS[number - 1]
    elif change == "extra_key":
        redaction["note"] = "x"
    elif change == "extra_placeholder":
        brief = brief + b"\n<workspace>/x\n"
    else:
        redaction["substitutions"].pop()
    return number, redaction, row, brief


@pytest.mark.parametrize("change", ["count", "to", "from_digest", "published", "reviewed", "brief_path", "extra_key",
                                    "extra_placeholder", "missing_substitution"])
def test_the_brief_redaction_is_as_stated(change):
    status = _status()
    profile.check_redaction(1, status["briefRedactions"][0], status["reviews"][0],
                            profile._verified(profile.HISTORY_BRIEFS[0]))
    with pytest.raises(ValueError, match=re.escape("a brief redaction is as stated: brief 1")):
        profile.check_redaction(*_redaction_mutant(1, change))


ORACLE_MESSAGE = "the oracle identity binds the oracle file, with ruling KEEP by the lane monitor"


def _oracle_mutant(change):
    identity = json.loads(profile._verified(profile.ORACLE_IDENTITY_PATH))
    oracle, row = profile._verified(profile.ORACLE_TEST), _status()["oracle"]
    identity_raw = None
    if change == "decision":
        identity["ruling"]["decision"] = "NONE_NEEDED"
    elif change == "by":
        identity["ruling"]["by"] = "OWNER"
    elif change == "ref":
        identity["ruling"]["ref"] = "MON-LIVE003-ORACLE-KEEP"
    elif change == "date":
        identity["ruling"]["date"] = "2026-10-24"
    elif change == "schema":
        identity["schemaVersion"] = "planeon.oracle-identity/v2"
    elif change == "file_digest":
        identity["file"]["sha256"] = _flip(identity["file"]["sha256"])
    elif change == "file_path":
        identity["file"]["path"] = profile.HEAD_TEST
    elif change == "identity_bytes":
        identity_raw = json.dumps(identity, indent=2).encode("utf-8")
    elif change == "oracle_bytes":
        oracle = oracle + b"\n"
    elif change == "row_test":
        row["test"] = profile.HEAD_TEST
    elif change == "row_identity":
        row["identity"] = profile.STATUS_PATH
    elif change == "row_digest":
        row["sha256"] = _flip(row["sha256"])
    elif change == "row_result":
        row["result"] = "86/86"
    else:
        oracle = None
    if identity_raw is None:
        identity_raw = profile._verified(profile.ORACLE_IDENTITY_PATH) if change in (
            "oracle_bytes", "row_test", "row_identity", "row_digest", "row_result", "not_bytes") else json.dumps(
            identity, indent=1).encode("utf-8")
    return identity_raw, oracle, row


@pytest.mark.parametrize("change", ["decision", "by", "ref", "date", "schema", "file_digest", "file_path",
                                    "identity_bytes", "oracle_bytes", "row_test", "row_identity", "row_digest",
                                    "row_result", "not_bytes"])
def test_the_oracle_identity_binds_the_oracle_file_with_keep(change):
    identity_raw, oracle = profile._verified(profile.ORACLE_IDENTITY_PATH), profile._verified(profile.ORACLE_TEST)
    profile.check_oracle_identity(identity_raw, oracle, _status()["oracle"])
    identity = json.loads(identity_raw)
    assert identity["candidateCommit"] == "f037014cfd0c34380c4c2048110032971aa83dbb"
    assert identity["ruling"] == {"decision": "KEEP", "by": "LANE_MONITOR", "ref": (
        "MON-LIVE003-ORACLE-KEEP; disclosed interruptions: a 429 stop and resume, the slot re-derivation, and the "
        "parser-marker resume after MON-LIVE003-ADOPT-C5"), "date": "2026-10-23"}
    with pytest.raises(ValueError, match=re.escape(ORACLE_MESSAGE)):
        profile.check_oracle_identity(*_oracle_mutant(change))


# The contract: the v1/ files, the source and reviews, A8's forward pin, the model and the replay -------------------------

HANDOFF = "the four v1/ files are the handoff bytes the binding states"


def _handoff_mutant(change):
    binding, files = _binding(), _v1()
    if change == "file_bytes":
        files["MANIFEST.json"] = files["MANIFEST.json"] + b" "
    elif change == "file_missing":
        del files["README.md"]
    elif change == "file_extra":
        files["probe-interface.v2.json"] = files["probe-interface.json"]
    elif change == "file_not_bytes":
        files["probe-interface.json"] = files["probe-interface.json"].decode("utf-8")
    elif change == "row_digest":
        binding["files"][2]["sha256"] = _flip(binding["files"][2]["sha256"])
    elif change == "row_path":
        binding["files"][1]["path"] = profile.CONTRACT_DIR + "/README.md"
    elif change == "row_order":
        binding["files"][0], binding["files"][1] = binding["files"][1], binding["files"][0]
    elif change == "row_missing":
        binding["files"].pop()
    else:
        binding["files"][0]["mode"] = "100644"
    return binding, files


@pytest.mark.parametrize("change", ["file_bytes", "file_missing", "file_extra", "file_not_bytes", "row_digest", "row_path",
                                    "row_order", "row_missing", "row_extra_member"])
def test_the_v1_files_are_the_handoff_bytes_the_binding_states(change):
    profile.check_handoff(_binding(), _v1())
    assert dict(profile.HANDOFF_SHA256) == _models()[0].HANDOFF
    assert [row["sha256"] for row in _binding()["files"]] == [profile.HANDOFF_SHA256[name] for name in profile.V1_NAMES]
    with pytest.raises(ValueError, match=re.escape(HANDOFF)):
        profile.check_handoff(*_handoff_mutant(change))


SOURCE = "the binding's source and reviews are the MANIFEST's, the last verdict PASS_FOR_HANDOFF"


def _source_mutant(change):
    binding, manifest = _binding(), json.loads(_v1()["MANIFEST.json"])
    if change == "source_commit":
        binding["source"]["commit"] = "1" * 40
    elif change == "source_extra":
        binding["source"]["branch"] = "main"
        manifest["source"]["branch"] = "main"
    elif change == "source_missing":
        del binding["source"]["readAt"]
        del manifest["source"]["readAt"]
    elif change == "source_list":
        binding["source"] = list(binding["source"].items())
    elif change == "review_digest":
        binding["reviews"][0]["recordSha256"] = _flip(binding["reviews"][0]["recordSha256"])
    elif change == "review_round":
        binding["reviews"][1]["round"] = 4
    elif change == "review_dropped":
        binding["reviews"].pop(0)
    elif change == "review_extra_member":
        binding["reviews"][2]["identitySha256"] = manifest["reviews"][2]["identitySha256"]
    elif change == "last_verdict":
        binding["reviews"][2]["verdict"] = "CHANGES_REQUIRED"
        manifest["reviews"][2]["verdict"] = "CHANGES_REQUIRED"
    elif change == "manifest_verdict":
        manifest["verdict"] = "CHANGES_REQUIRED"
    elif change == "manifest_source":
        manifest["source"]["tree"] = "2" * 40
    else:
        binding["reviews"], manifest["reviews"] = [], []
    return binding, json.dumps(manifest, indent=1).encode("utf-8")


@pytest.mark.parametrize("change", ["source_commit", "source_extra", "source_missing", "source_list", "review_digest",
                                    "review_round", "review_dropped", "review_extra_member", "last_verdict",
                                    "manifest_verdict", "manifest_source", "no_reviews"])
def test_the_binding_source_and_reviews_are_the_manifests(change):
    binding, manifest_raw = _binding(), _v1()["MANIFEST.json"]
    profile.check_source(binding, manifest_raw)
    assert binding["source"]["commit"] == "c17bcfe32df26eab13844b73f65666bb0fa4e0a0"
    assert [row["verdict"] for row in binding["reviews"]] == ["CHANGES_REQUIRED", "CHANGES_REQUIRED", "PASS_FOR_HANDOFF"]
    with pytest.raises(ValueError, match=re.escape(SOURCE)):
        profile.check_source(*_source_mutant(change))


PIN = "the placeholder binding names LPK-0's merged record and the interface by this era's digests"


def _pin_mutant(change):
    binding, pin, lpk0, interface = _binding(), dict(profile.STATUS_PIN), _lpk0(), _v1()["probe-interface.json"]
    placeholder = binding["placeholderBinding"]
    if change == "record_path":
        placeholder["record"] = "architecture/probe-kit-scope/vectors.json"
    elif change == "record_digest":
        placeholder["recordSha256"] = "cf49670d" + placeholder["recordSha256"][8:]
    elif change == "placeholder":
        placeholder["placeholder"] = "R12_SUCCESSOR"
    elif change == "bound_to":
        placeholder["boundTo"] = "MET-LIVE-004"
    elif change == "interface_digest":
        placeholder["interfaceSha256"] = _flip(placeholder["interfaceSha256"])
    elif change == "extra_member":
        placeholder["note"] = "x"
    elif change == "lpk0_bytes":
        lpk0 = lpk0 + b"\n"
    elif change == "lpk0_without_placeholder":
        record = json.loads(lpk0)
        record["effectivePredecessors"]["placeholders"].remove("NEUTRAL_INTERFACE_CONTRACT")
        lpk0 = json.dumps(record, indent=1).encode("utf-8")
        placeholder["recordSha256"] = profile.digest(lpk0)
        pin["sha256"] = profile.digest(lpk0)
    elif change == "pin_record":
        pin["record"] = "architecture/probe-kit-scope/README.md"
    elif change == "pin_digest":
        pin["sha256"] = _flip(pin["sha256"])
    elif change == "interface_bytes":
        interface = interface + b" "
    else:
        lpk0 = None
    return binding, pin, lpk0, interface


@pytest.mark.parametrize("change", ["record_path", "record_digest", "placeholder", "bound_to", "interface_digest",
                                    "extra_member", "lpk0_bytes", "lpk0_without_placeholder", "pin_record", "pin_digest",
                                    "interface_bytes", "lpk0_not_bytes"])
def test_the_placeholder_binding_is_a8s_forward_pin(change):
    binding, lpk0 = _binding(), _lpk0()
    profile.check_placeholder(binding, _status()["predecessorPin"], lpk0, _v1()["probe-interface.json"])
    assert binding["placeholderBinding"]["recordSha256"] == profile.digest(lpk0) == profile.ERA_SHA256[profile.LPK0_RECORD]
    assert "NEUTRAL_INTERFACE_CONTRACT" in json.loads(lpk0)["effectivePredecessors"]["placeholders"]
    with pytest.raises(ValueError, match=re.escape(PIN)):
        profile.check_placeholder(*_pin_mutant(change))


def test_the_reference_model_returns_no_refusal_and_each_binding_mutant_is_refused():
    model = _models()[0]
    binding, files, lpk0 = _binding(), _v1(), _lpk0()
    read = profile._reader(files, lpk0)
    profile.check_model(model.check(binding, read))
    mutants = [dict(binding, slot=263), dict(binding, nonClaims=binding["nonClaims"][1:]),
               dict(binding, placeholderBinding=dict(binding["placeholderBinding"], boundTo="MET-LIVE-004"))]
    for mutant in mutants:
        refusals = model.check(mutant, read)
        assert refusals
        with pytest.raises(ValueError, match="the reference model returns no refusal for the adopted binding"):
            profile.check_model(refusals)
    changed = profile._reader(dict(files, **{"README.md": files["README.md"] + b"\n"}), lpk0)
    assert model.R["sha"] in model.check(binding, changed)
    assert model.R["placeholder"] in model.check(binding, profile._reader(files, lpk0 + b"\n"))
    for value in (None, ["x"], ()):
        with pytest.raises(ValueError, match="the reference model returns no refusal for the adopted binding"):
            profile.check_model(value)


def test_the_layers_replay_restates_replay_py_vector_by_vector():
    """The layer's _apply, _v1_files and _reader equal replay.py's apply, files_for and reader on every vector, and each
    validator vector's verdict through the model's check equals the model's own valid and the vector's expectation."""
    model, replay = _models()[0], _replay_py()
    binding, vectors, files, lpk0 = _binding(), _vectors(), _v1(), _lpk0()
    assert (profile.SHAPE_REFUSAL, profile.KEYWORD_REFUSAL, profile.CONFORMANCE_REFUSAL) == (
        model.R["shape"], model.R["keyword"], model.R["conformance"])
    assert profile.V1_DIR == model.DIRECTORY and profile.LPK0_RECORD == model.LPK0_RECORD
    assert profile.V1_NAMES == model.FILES
    for vector in vectors["negatives"]:
        assert profile._apply(binding, vector["recordOps"]) == replay.apply(binding, vector["recordOps"])
        assert profile._v1_files(files, vector["fileOverrides"]) == replay.files_for(files, vector["fileOverrides"])
    ours, theirs = profile._reader(files, lpk0), replay.reader(model, files, lpk0)
    for path in list(profile.V1_FILES) + [profile.LPK0_RECORD, profile.V1_DIR + "x.json", profile.BINDING_PATH]:
        assert ours(path) == theirs(path), path
    instance, schema = json.loads(files["probe-interface.json"]), json.loads(files["probe-interface.schema.json"])
    for vector in vectors["validatorVectors"]:
        i, s = profile._apply(instance, vector["instanceOps"]), profile._apply(schema, vector["schemaOps"])
        assert i == replay.apply(instance, vector["instanceOps"]) and s == replay.apply(schema, vector["schemaOps"])
        swapped = dict(files, **{"probe-interface.json": json.dumps(i, ensure_ascii=False).encode("utf-8"),
                                 "probe-interface.schema.json": json.dumps(s, ensure_ascii=False).encode("utf-8")})
        refusals = model.check(binding, profile._reader(swapped, lpk0))
        assert model.R["shape"] not in refusals and model.R["keyword"] not in refusals, vector["label"]
        assert (model.R["conformance"] not in refusals) == model.valid(i, s, s) == vector["valid"], vector["label"]


REPLAY = "the vectors replay with one positive, 28 negatives and 15 validator vectors, and no mismatch"


def _replay_mutant(change):
    vectors = _vectors()
    if change == "positive":
        vectors["positive"]["refusals"] = [profile.SHAPE_REFUSAL]
    elif change == "negative_refusals":
        vectors["negatives"][0]["refusals"] = vectors["negatives"][0]["refusals"][1:]
    elif change == "negative_dropped":
        vectors["negatives"].pop()
    elif change == "negative_added":
        vectors["negatives"].append(dict(vectors["negatives"][-1], label="a copy"))
    elif change == "validator_flipped":
        vectors["validatorVectors"][1]["valid"] = True
    elif change == "validator_keyword":
        vectors["validatorVectors"][0]["schemaOps"] = [{"op": "set", "path": "/maxLength", "value": 3}]
    elif change == "validator_instance":
        vectors["validatorVectors"][0]["instanceOps"] = [{"op": "set", "path": "", "value": [[[[]]]]}]
    else:
        vectors["validatorVectors"].pop()
    return vectors


@pytest.mark.parametrize("change", ["positive", "negative_refusals", "negative_dropped", "negative_added",
                                    "validator_flipped", "validator_keyword", "validator_instance", "validator_dropped"])
def test_the_vectors_replay_with_one_positive_28_negatives_and_15_validator_vectors(change):
    model, replay = _models()[0], _replay_py()
    binding, vectors, files, lpk0 = _binding(), _vectors(), _v1(), _lpk0()
    result = profile.replay(model, binding, vectors, files, lpk0)
    profile.check_replay(result)
    assert result == replay.run(model, binding, vectors, files, lpk0) == {
        "positive": 1, "negatives": 28, "validatorVectors": 15, "mismatches": []}
    with pytest.raises(ValueError, match=re.escape(REPLAY)):
        profile.check_replay(profile.replay(model, binding, _replay_mutant(change), files, lpk0))
    for value in (None, dict(result, mismatches=[("x", [])]), dict(result, negatives=27), []):
        with pytest.raises(ValueError, match=re.escape(REPLAY)):
            profile.check_replay(value)


# The registry, unchanged, and the derived gate check --------------------------------------------------------------------

REGISTRY_MESSAGE = "the registry is 261's, unchanged, with exactly this packet's PACKET series pinning its brief"


def _registry_mutant(change):
    raw, brief = profile._verified(profile.REGISTRY_PATH), profile._verified(profile.PACKET_BRIEF)
    registry = json.loads(raw)
    entry = [row for row in registry["briefs"] if row["series"] == "MET-LIVE-003/packet"][0]
    if change == "registry_bytes":
        return raw + b"\n", brief
    if change == "brief_bytes":
        return raw, brief + b"\n"
    if change == "brief_not_bytes":
        return raw, None
    if change == "not_bytes":
        return raw.decode("utf-8"), brief
    if change == "contract_entry":
        registry["briefs"].append(dict(entry, kind="CONTRACT", series="MET-LIVE-003/contract",
                                       path="architecture/review-briefs/REVIEW_BRIEF_CONTRACT.md"))
    elif change == "packet_dropped":
        registry["briefs"].remove(entry)
    elif change == "packet_kind":
        entry["kind"] = "CONTRACT"
    elif change == "packet_digest":
        entry["sha256"] = _flip(entry["sha256"])
    else:
        entry["version"] = 2
    return (json.dumps(registry, indent=1) + "\n").encode("ascii"), brief


@pytest.mark.parametrize("change", ["registry_bytes", "brief_bytes", "brief_not_bytes", "not_bytes", "contract_entry",
                                    "packet_dropped", "packet_kind", "packet_digest", "packet_version"])
def test_the_registry_is_261s_unchanged_with_this_packets_packet_series(change):
    raw = profile._verified(profile.REGISTRY_PATH)
    profile.check_registry(raw, profile._verified(profile.PACKET_BRIEF))
    registry = json.loads(raw)
    assert len(registry["briefs"]) == 8
    assert [row["series"] for row in registry["briefs"] if row["series"].startswith("MET-LIVE-003")] == [
        "MET-LIVE-003/packet"]
    with pytest.raises(ValueError, match=re.escape(REGISTRY_MESSAGE)):
        profile.check_registry(*_registry_mutant(change))


def _gate_mutant(change):
    gate = deepcopy(_gate())
    if change == "drop":
        gate.pop()
    elif change == "extra":
        gate.append({"exact": "README.md"})
    elif change == "under_name":
        gate[-1] = {"under": "architecture/", "name": "REVIEW_BRIEF*.md"}
    elif change == "two_keys":
        gate[0] = dict(gate[0], prefix="x/")
    elif change == "not_dict":
        gate[0] = "AGENTS.md"
    else:
        gate = tuple(gate)
    return gate


@pytest.mark.parametrize("change", ["drop", "extra", "under_name", "two_keys", "not_dict", "not_list"])
def test_the_gate_list_is_31_exact_or_prefix_entries(change):
    profile.check_gate_list(_gate())
    with pytest.raises(ValueError, match="the evolution surface record derives 31 exact or prefix gate entries"):
        profile.check_gate_list(_gate_mutant(change))


GATE_MESSAGE = "the packet's changed files hold no gate path"


def _hits_mutant(change):
    changed = _changed()
    if change == "registry":
        changed = sorted(changed + [profile.REGISTRY_PATH])
    elif change == "surface_record":
        changed = sorted(changed + [profile.SURFACE_RECORD])
    elif change == "gate_prefix":
        changed = sorted(changed + ["ci/linux-runner/runner.py"])
    elif change == "case_variant":
        changed = sorted(changed + ["Architecture/Review-Record/Briefs.json"])
    elif change == "schema":
        changed = sorted(changed + ["schemas/x.schema.json"])
    elif change == "harness_docs":
        changed = sorted(changed + ["docs/harnesses/x.md"])
    elif change == "unsorted":
        changed.reverse()
    else:
        changed = tuple(changed)
    return _gate(), changed


@pytest.mark.parametrize("change", ["registry", "surface_record", "gate_prefix", "case_variant", "schema",
                                    "harness_docs", "unsorted", "not_list"])
def test_the_packets_changed_files_hold_no_gate_path(change):
    gate, changed = _gate(), _changed()
    profile.check_gate_hits(gate, changed)
    assert profile.gate_paths(gate, changed) == []
    surface = _models()[1]
    record = json.loads(profile._verified(profile.SURFACE_RECORD))
    # Data, not gate material: the model's own approvers of the changed files are the lane monitor or the owner.
    assert surface.pr_approvers(record, changed) == ["LANE_MONITOR", "OWNER"]
    assert surface.resolve(record, profile.ORACLE_TEST) == "ORACLE_TESTS"
    for path in profile.NEW_FILES[:-1] + (profile.HEAD_TEST, profile.VALIDATOR_PATH, profile.AUTHORITY_PATH):
        assert surface.resolve(record, path) == "CONTRACT_AND_SOURCE", path
    with pytest.raises(ValueError, match=re.escape(GATE_MESSAGE)):
        profile.check_gate_hits(*_hits_mutant(change))


# The canonical inverse hunks -------------------------------------------------------------------------------------------

def test_the_canonical_check_reads_this_eras_bytes():
    path, rule = next(iter(profile._PROJECTION_RULES.items()))
    after = profile.reviewed_bytes(path)
    profile.check_canonical_hunks(path, rule, after)
    with pytest.raises(ValueError, match=re.escape("unreviewed current source: " + path)):
        profile.check_canonical_hunks(path, rule, after + b" ")


def test_every_recorded_hunk_is_canonical_and_reconstructs():
    for path, rule in profile._PROJECTION_RULES.items():
        after = profile.reviewed_bytes(path)
        before = profile._undo_this_layer(path, after)
        hunks = profile.canonical_hunks(after, before)
        assert hunks == rule["reverseHunks"] and profile._inverse(after, hunks) == before


def _line_hunks(after, before):
    import difflib
    current, previous = after.splitlines(keepends=True), before.splitlines(keepends=True)
    offsets = [0]
    for line in current:
        offsets.append(offsets[-1] + len(line))
    return tuple((offsets[a], b"".join(current[a:b]), b"".join(previous[c:d]))
                 for tag, a, b, c, d in difflib.SequenceMatcher(None, current, previous, autojunk=False).get_opcodes()
                 if tag != "equal")


def test_whole_line_hunks_are_refused_where_canonical_ones_differ():
    for path, rule in profile._PROJECTION_RULES.items():
        after = profile.reviewed_bytes(path)
        before = profile._undo_this_layer(path, after)
        line = _line_hunks(after, before)
        if line != rule["reverseHunks"]:
            break
    assert profile._inverse(after, line) == before
    with pytest.raises(ValueError, match=re.escape("canonical byte-minimal inverse hunks: " + path)):
        profile.check_canonical_hunks(path, dict(rule, reverseHunks=line), after)


# Every check can fail (252's packet review lesson P1-1: no check without a failing test) ------------------------------

SEMANTIC_FUNCTIONS = {"_era_bytes", "_verified", "check_freeze", "check_new_files", "check_added_file", "check_status",
                      "check_adoptions", "check_subject", "check_review_lists", "check_review", "check_redaction",
                      "check_oracle_identity", "check_handoff", "check_source", "check_placeholder", "check_model",
                      "check_replay", "check_registry", "check_gate_list", "check_gate_hits"}
CHECK_TESTS = {
    "MET-LIVE-003 reviewed bytes are bound: ": "test_a_path_outside_the_era_is_refused_before_it_is_read",
    "unreviewed LINUX-PROBE-INTERFACE source: ": "test_every_era_file_is_bound_by_digest",
    FREEZE: "test_the_freeze_refuses_every_other_change",
    "this packet adds exactly its contract files, adoption records, oracle test and layer test, each once":
        "test_the_packet_adds_exactly_its_files_each_once",
    "a file this packet adds is a regular file of git mode 100644: ":
        "test_an_added_file_is_a_regular_file_of_mode_100644_without_a_local_path",
    "no absolute local path in a file this packet adds: ":
        "test_an_added_file_is_a_regular_file_of_mode_100644_without_a_local_path",
    "adopted LINUX-PROBE-INTERFACE status": "test_the_status_is_closed_and_records_the_adoption",
    "the adoptions run c2 to c6 with their rulings and ADOPTION_CHECK digests":
        "test_the_adoptions_run_c2_to_c6_with_their_check_digests",
    "status.json names the adopted subject by digest": "test_status_names_the_adopted_subject_by_digest",
    "the adopted files are the adopted subject's bytes: ": "test_the_adopted_files_are_the_adopted_subjects_bytes",
    "every review and brief redaction is recorded": "test_every_review_and_redaction_is_recorded",
    "a review is bound to its published record and brief: review ":
        "test_the_light_review_is_bound_to_its_published_record_and_brief",
    "a brief redaction is as stated: brief ": "test_the_brief_redaction_is_as_stated",
    ORACLE_MESSAGE: "test_the_oracle_identity_binds_the_oracle_file_with_keep",
    HANDOFF: "test_the_v1_files_are_the_handoff_bytes_the_binding_states",
    SOURCE: "test_the_binding_source_and_reviews_are_the_manifests",
    PIN: "test_the_placeholder_binding_is_a8s_forward_pin",
    "the reference model returns no refusal for the adopted binding":
        "test_the_reference_model_returns_no_refusal_and_each_binding_mutant_is_refused",
    REPLAY: "test_the_vectors_replay_with_one_positive_28_negatives_and_15_validator_vectors",
    REGISTRY_MESSAGE: "test_the_registry_is_261s_unchanged_with_this_packets_packet_series",
    "the evolution surface record derives 31 exact or prefix gate entries":
        "test_the_gate_list_is_31_exact_or_prefix_entries",
    GATE_MESSAGE: "test_the_packets_changed_files_hold_no_gate_path",
    "unreviewed current source: ": "test_the_canonical_check_reads_this_eras_bytes",
    "canonical byte-minimal inverse hunks: ": "test_whole_line_hunks_are_refused_where_canonical_ones_differ"}
NAMED_MESSAGES = {FREEZE: "FREEZE", ORACLE_MESSAGE: "ORACLE_MESSAGE", HANDOFF: "HANDOFF", SOURCE: "SOURCE", PIN: "PIN",
                  REPLAY: "REPLAY", REGISTRY_MESSAGE: "REGISTRY_MESSAGE", GATE_MESSAGE: "GATE_MESSAGE"}


def _refusal_messages():
    """The constant text of every refusal in the semantic check's functions and the canonical-hunk guard: a require or
    _bound call's message, cut at its first format field."""
    tree = ast.parse(profile.regular_bytes(profile.VALIDATOR_PATH))
    found = set()
    for node in tree.body:
        if not (isinstance(node, ast.FunctionDef)
                and node.name in SEMANTIC_FUNCTIONS | {"check_canonical_hunks", "validate_canonical_hunks"}):
            continue
        for call in ast.walk(node):
            if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                    and call.func.id in ("require", "_bound") and len(call.args) == 2):
                continue
            message = call.args[1]
            while isinstance(message, ast.BinOp):
                message = message.left
            if isinstance(message, ast.Name):
                assert message.id == "message", ast.dump(call)   # _bound's own pass-through
                continue
            assert isinstance(message, ast.Constant) and type(message.value) is str, ast.dump(call)
            found.add(message.value.split("%")[0])
    return found


def _messages_of(name):
    """The expected messages a parametrized test lists in its parametrize marks."""
    rows = []
    for mark in getattr(globals()[name], "pytestmark", []):
        values = mark.args[1] if len(mark.args) > 1 else []
        for row in values:
            rows += [value for value in (row if isinstance(row, tuple) else (row,)) if isinstance(value, str)]
    return rows


def test_every_check_has_a_test_that_makes_it_fail():
    """Every refusal of the semantic check is mapped to a test, and that test names the refusal (in its body, its
    parametrized expected messages, or the module constant that holds it)."""
    import inspect
    assert _refusal_messages() == set(CHECK_TESTS)
    for message, name in CHECK_TESTS.items():
        test = globals()[name]
        assert callable(test) and name.startswith("test_")
        source = inspect.getsource(test)
        assert (message[:40] in source or any(message.startswith(text) for text in _messages_of(name))
                or (message in NAMED_MESSAGES and NAMED_MESSAGES[message] in source)), message
