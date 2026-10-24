"""Exact source lineage for MET-GOV-003; the evolution surface record version 3 (the Linux probe kit's top-level data directory linux-probe-kit/ as CONTRACT_AND_SOURCE) with the D5a oracle edit, its re-issued identity and the MET-LIVE-004 brief registry entries: the head keeps the full fan-in (8 own and 72 predecessor routes, every catalog walk and round trip, the full payload loop), and the semantic check (the freeze, the file added, the adopted record, vectors and README, the record's and the vectors' change from version 2, the unchanged model over version 3 with the kit prefix's resolution, the registry, the oracle edit and its identity, the derived gate check, and the canonical hunks) has a failing case for every refusal, each on plain data."""
import ast
import json
from copy import deepcopy
import os
import re
import stat
from pathlib import Path
from types import MappingProxyType

import pytest

from scripts import validate_linux_probe_kit_gate as profile
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


def changed_test():
    return next(path for path in profile._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert profile.validate() is None
    current = packets()
    accepted = profile.historical_catalog(current)
    assert len(current) == 261 and len(accepted) == 260
    assert set(accepted) == set(current) - {profile.NEW_PACKET}
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
        raw = profile.regular_bytes(path)
        assert profile.digest(raw) == rule["afterSha256"]
        before = profile.historical_bytes(path, raw)
        assert profile.digest(before) == rule["beforeSha256"]
        assert profile.historical_bytes(path, before) == before


@pytest.mark.parametrize("fault", ["missing_new", "missing_old", "extra", "new_payload", "old_payload", "projected"])
def test_catalog_refuses_all_packet_substitution_and_loss(fault):
    current = deepcopy(packets())
    if fault == "missing_new":
        current.pop(profile.NEW_PACKET)
    elif fault == "missing_old":
        current.pop("MET-RUNNER-001")
    elif fault == "extra":
        current["UNREVIEWED-001"] = {}
    elif fault == "projected":
        current = profile.historical_catalog(current)
    else:
        name = profile.NEW_PACKET if fault == "new_payload" else "MET-001"
        current[name]["objective"] += " unreviewed"
    with pytest.raises(ValueError):
        profile.validate_packet_payloads(current)


def test_every_predecessor_payload_is_checked_without_a_verdict_cache():
    current = packets()
    profile.validate_packet_payloads(current)
    for name in sorted(profile.authority()["baselinePackets"]):
        original = current[name]
        current[name] = dict(original, objective=original["objective"] + " unreviewed")
        with pytest.raises(ValueError, match="changed packet payload"):
            profile.validate_packet_payloads(current)
        current[name] = original


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


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "pks_old", "rrv_old", "pod_old", "evs_old", "e9_old", "ccomp_old", "i6v4_old", "dcap_old", "np5_old", "lrp_old", "wpa3_old", "cfp3_old", "sol_old", "mx6_old", "np4_old", "tcv1_old", "wpa2_old", "la2_old", "i5v4_old", "cdh_old", "cfp2_old", "smx_old", "phr_old", "sv4_old", "hs43_old", "rav3_old", "deadlines_old", "events_old", "filters_old", "loop_old", "manifest_old", "ledger_old", "adoption_old", "amendment_old", "bprofile_old", "mprofile_old", "eprofile_old", "lprofile_old", "fprofile_old", "oprofile_old", "uprofile_old", "jprofile_old", "kprofile_old", "tprofile_old", "zprofile_old", "yprofile_old", "xprofile_old", "pprofile_old", "aprofile_old", "vprofile_old", "cprofile_old", "qprofile_old", "hprofile_old", "dprofile_old", "sprofile_old", "wprofile_old", "rprofile_old", "gprofile_old", "iprofile_old", "nprofile_old", "resolution_old", "account_old", "canary_old", "isolated_old", "portable_old", "proof_old", "recheck_old", "verifier_old", "linux_old", "performance_old", "runner_old", "roadmap_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = profile.historical_bytes(path, raw) if route in ("current_test", "old_bytes") else None
    current_packets = packets() if route in ("catalog", "payloads") else None
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
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
        "payloads": lambda: profile.validate_packet_payloads(current_packets),
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
    with pytest.raises(ValueError, match="linux probe kit gate history authority digest"):
        calls[route]()


def test_catalog_uses_only_pinned_parsed_data_and_checks_each_input_again(monkeypatch):
    current = packets()
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
    assert len(profile.historical_catalog(current)) == 260


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
    assert len(profile.historical_catalog(current)) == 260
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
    assert len(rules) == 261 and len(parsed) == 260
    assert profile._packet_rules() is rules and len(parsed) == 260
    with pytest.raises(TypeError):
        rules["MET-001"] = ("0" * 64, "0" * 64)


def test_first_full_packet_check_refuses_changed_old_yaml(monkeypatch):
    current = packets()
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
    current = packets()
    profile.validate_packet_payloads(current)
    current["MET-001"]["objective"] += " unreviewed"
    with pytest.raises(ValueError, match="changed packet payload: MET-001"):
        profile.validate_packet_payloads(current)
    original = profile.regular_bytes

    def changed_reader(path):
        raw = original(path)
        return raw + b" " if path == profile.AUTHORITY_PATH else raw

    monkeypatch.setattr(profile, "regular_bytes", changed_reader)
    with pytest.raises(ValueError, match="linux probe kit gate history authority digest"):
        profile.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = packets()
    profile.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "linux-probe-kit-gate-authority.json").write_bytes(
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
        profile.validate_packet_payloads(current)


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
    with pytest.raises(ValueError, match="linux probe kit gate validator drift"):
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
            assert all("validate_" not in alias.name for alias in node.names)


def _count_authority_reads(monkeypatch):
    counts = {}
    for module in (profile, pks, rrv, pod, evs, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner):
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
    expected = {module.__name__: 1 for module in (profile, pks, rrv, pod, evs, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner)}
    if route == "current_test":
        # The forward route reads this layer's newest bytes and then projects them forward once more.
        assert all(counts[name] >= 1 for name in expected) and set(counts) == set(expected)
    else:
        assert counts == expected


# MET-GOV-003 (LINUX-PROBE-KIT-GATE): this era's check, and a failing case for every check. Every mutant below is applied
# to plain data handed to the layer's pure checks: nothing in the layer or the library is patched or swapped. The mutants
# are built by the pure helpers _<area>_mutant(change), one change name per mutant. The evolution surface model is
# executed from this era's verified bytes through the layer's era loader; this test also calls the model's own
# pr_approvers, which the layer does not (it derives a one-path PR's approvers from resolve and the record, since
# pr_approvers is not an attribute name the frozen allow-list admits), and the two must agree.

VALIDATE = profile.validate_linux_probe_kit_gate
# Tamper values name paths that already exist and that this packet does not carry in the tampered place.
OTHER_PATH = "scripts/validate_probe_kit_scope.py"
_CACHE = {}


def _model():
    if "model" not in _CACHE:
        _CACHE["model"] = profile.era_model()
    return _CACHE["model"]


def _before(path):
    """260's merged bytes of a changed earlier contract file, through the layer's own inverse."""
    return profile._undo_this_layer(path, profile._verified(path))


def _record():
    return json.loads(profile._verified(profile.RECORD_PATH))


def _base():
    return json.loads(_before(profile.RECORD_PATH))


def _changed():
    record = profile.authority()
    return sorted(set(record["changedFiles"]) | set(record["newFiles"])
                  | {profile.AUTHORITY_PATH, profile.VALIDATOR_PATH, profile.PACKET_PATH})


def _gate():
    return _model().check(_base())["gateMaterial"]


def _serial(value, **options):
    """This test's own form of the record's serialization (one-space indent, ASCII escapes, a final newline)."""
    return (json.dumps(value, **dict({"indent": 1}, **options)) + "\n").encode("ascii")


def _class(record, cls):
    return [item for item in record["levels"]["programme"]["classes"] if item["id"] == cls][0]


def _flip(text):
    """A different lowercase hex digest of the same length."""
    return text[:-1] + ("0" if text[-1] != "0" else "1")


def test_the_contract_holds_for_this_era():
    assert VALIDATE() is None


def test_the_era_holds_the_changed_contract_the_two_briefs_and_the_model():
    assert set(profile.ERA_SHA256) == set(profile.CHANGED_CONTRACT) | {profile.PACKET_BRIEF, profile.CONTRACT_BRIEF,
                                                                       profile.SURFACE_MODEL}
    assert len(profile.ERA_SHA256) == 9 and profile.NEW_FILES == ("tests/test_linux_probe_kit_gate.py",)
    assert profile.GATE_HITS == ("architecture/evolution-surface/evolution-surface.json",
                                 "architecture/evolution-surface/vectors.json",
                                 "architecture/evolution-surface/README.md",
                                 "architecture/review-record/oracle-identity-evolution-surface.json",
                                 "architecture/review-record/briefs.json")
    assert set(profile.BASE_SHA256) == set(profile.CHANGED_CONTRACT) and set(profile.ADOPTED_SHA256) == set(
        profile.CONTRACT_FILES)
    for path, expected in profile.ADOPTED_SHA256.items():
        assert profile.ERA_SHA256[path] == expected
    assert profile.ERA_SHA256[profile.ORACLE_TEST] == profile.ORACLE_SHA256
    assert profile.ERA_SHA256[profile.ORACLE_IDENTITY_PATH] == profile.IDENTITY_SHA256
    for path, expected in profile.ERA_SHA256.items():
        assert profile.digest(profile.reviewed_bytes(path)) == expected


@pytest.mark.parametrize("path", sorted(profile.ERA_SHA256))
def test_every_era_file_is_bound_by_digest(path):
    raw = profile._verified(path)
    assert profile._era_bytes(path, raw) == raw
    for changed in (raw + b" ", bytearray(raw)):
        with pytest.raises(ValueError, match=re.escape("unreviewed LINUX-PROBE-KIT-GATE source: " + path)):
            profile._era_bytes(path, changed)


def test_a_path_outside_the_era_is_refused_before_it_is_read():
    for path in ("architecture/evolution-surface/evolution-surface.schema.json", "architecture/review-record/README.md",
                 "linux-probe-kit/x", OTHER_PATH, profile.VALIDATOR_PATH, profile.HEAD_TEST, profile.LIVING_CATALOGS[0],
                 None):
        with pytest.raises(ValueError, match="MET-GOV-003 reviewed bytes are bound: "):
            profile._verified(path)
        with pytest.raises(ValueError, match="MET-GOV-003 reviewed bytes are bound: "):
            profile._era_bytes(path, b"")


def test_the_era_model_is_executed_from_verified_bytes():
    model = profile.era_model()
    assert model.__name__ == "_met_gov_003_evolution_surface"
    assert model.__file__ == str(profile.ROOT / profile.SURFACE_MODEL)


# The freeze, the file this packet adds and the changed contract files' privacy -------------------------------------------

FREEZE = ("this packet edits only chain validators, tests, the three living catalogs, the record's three files, the "
          "oracle identity and the registry: ")


@pytest.mark.parametrize("path", ["scripts/evolution_surface.py", "scripts/review_record.py", "scripts/chain_identity.py",
                                  "scripts/probe_kit_scope.py", "architecture/review-record/README.md",
                                  "architecture/review-record/legacy-review-records.json",
                                  "architecture/review-record/oracle-identity.json",
                                  "architecture/evolution-surface/evolution-surface.schema.json",
                                  "architecture/evolution-surface/status.json", "architecture/probe-kit-scope/amendment.json",
                                  "architecture/review-briefs/REVIEW_BRIEF_PACKET.md", "docs/DEVELOPMENT_STATUS.md",
                                  "docs/linux-probe-kit/README.md", "linux-probe-kit/README.md", "tests/conftest.py",
                                  "conftest.py", "scripts/validate_x/y.py", "scripts/validate_x.txt",
                                  "ci/linux-runner/runner.py", "pyproject.toml", None])
def test_the_freeze_refuses_every_other_change(path):
    changed = list(profile._PROJECTION_RULES)
    assert set(profile.CHANGED_CONTRACT) <= set(changed)
    profile.check_freeze(changed)
    with pytest.raises(ValueError, match=re.escape(FREEZE)):
        profile.check_freeze(changed + [path])


def _added_mutant(change):
    added = [profile.HEAD_TEST]
    if change == "missing":
        added = []
    elif change == "extra":
        added.append("linux-probe-kit/README.md")
    elif change == "duplicate":
        added.append(profile.HEAD_TEST)
    elif change == "other":
        added = ["tests/test_linux_probe_kit.py"]
    else:
        added = tuple(added)
    return added


@pytest.mark.parametrize("change", ["missing", "extra", "duplicate", "other", "not_list"])
def test_the_packet_adds_exactly_its_layer_test(change):
    profile.check_new_files([profile.HEAD_TEST])
    profile.check_new_files(list(profile.authority()["newFiles"]))
    with pytest.raises(ValueError, match="this packet adds exactly its layer test"):
        profile.check_new_files(_added_mutant(change))


@pytest.mark.parametrize("path", profile.CHANGED_CONTRACT)
def test_a_changed_contract_file_holds_no_absolute_local_path(path):
    raw = profile._verified(path)
    profile.check_private(path, raw)
    for marker in (b"/" + b"Users/x", b"/" + b"private/tmp/x", b"~/.local" + b"/state/x", b"/" + b"USERS/1"):
        with pytest.raises(ValueError, match=re.escape("no absolute local path in a contract file this packet changes: "
                                                       + path)):
            profile.check_private(path, raw + marker)
    with pytest.raises(ValueError, match=re.escape("no absolute local path in a contract file this packet changes: ")):
        profile.check_private(path, raw.decode("utf-8"))
    profile.check_private(path, raw + b" /" + b"users, /" + b"private, .local" + b"/state, e-mail pattern")


# The adopted contract: c3's bytes; the record's and the vectors' change from 260's merged bytes ----------------------------

def _adopted_mutant(change):
    files = {path: profile._verified(path) for path in profile.CONTRACT_FILES}
    if change == "record":
        files[profile.RECORD_PATH] = _before(profile.RECORD_PATH)
    elif change == "vectors":
        files[profile.VECTORS_PATH] = files[profile.VECTORS_PATH] + b"\n"
    elif change == "readme":
        files[profile.README_PATH] = _before(profile.README_PATH)
    elif change == "missing":
        del files[profile.README_PATH]
    elif change == "not_bytes":
        files[profile.RECORD_PATH] = bytearray(files[profile.RECORD_PATH])
    else:
        files = list(files.items())
    return files


@pytest.mark.parametrize("change", ["record", "vectors", "readme", "missing", "not_bytes", "not_dict"])
def test_the_record_vectors_and_readme_are_the_adopted_c3_bytes(change):
    profile.check_adopted({path: profile._verified(path) for path in profile.CONTRACT_FILES})
    assert profile.ADOPTED_SHA256[profile.RECORD_PATH] == profile.ERA_SHA256[profile.RECORD_PATH]
    with pytest.raises(ValueError, match=re.escape("the record, vectors and README are the adopted c3 bytes: ")):
        profile.check_adopted(_adopted_mutant(change))


@pytest.mark.parametrize("path", sorted(profile.BASE_SHA256))
def test_260s_merged_bytes_are_bound(path):
    before = _before(path)
    profile.check_before(path, before)
    assert profile.digest(before) == profile.BASE_SHA256[path] != profile.ERA_SHA256[path]
    for raw, where in ((before + b" ", path), (profile._verified(path), path), (bytearray(before), path),
                       (before, OTHER_PATH)):
        with pytest.raises(ValueError, match=re.escape("260's merged bytes are bound: " + where)):
            profile.check_before(where, raw)


RECORD_CHANGES = ["version_4", "version_unchanged", "entry_first", "entry_case", "entry_exact", "entry_missing",
                  "two_entries", "other_class", "description", "grounds", "independent_of", "skip_rule", "key_order",
                  "indent", "no_newline", "base_bytes", "base_version", "release_not_last"]


def _record_mutant(change):
    before = _before(profile.RECORD_PATH)
    record, base = _record(), _base()
    paths = _class(record, "CONTRACT_AND_SOURCE")["paths"]
    if change == "version_4":
        record["version"] = 4
    elif change == "version_unchanged":
        record["version"] = 2
    elif change == "entry_first":
        paths.insert(0, paths.pop())
    elif change == "entry_case":
        paths[-1] = {"prefix": "Linux-Probe-Kit/"}
    elif change == "entry_exact":
        paths[-1] = {"exact": "linux-probe-kit/README.md"}
    elif change == "entry_missing":
        paths.pop()
    elif change == "two_entries":
        paths.append({"prefix": "linux-probe-kit-docs/"})
    elif change == "other_class":
        _class(record, "REPOSITORY_ROOT")["paths"].append(paths.pop())
    elif change == "description":
        _class(record, "CONTRACT_AND_SOURCE")["description"] += " The Linux probe kit too."
    elif change == "grounds":
        _class(record, "CONTRACT_AND_SOURCE")["grounds"].append("owner Q-PK-1: New data directory (Recommended)")
    elif change == "independent_of":
        _class(record, "CONTRACT_AND_SOURCE")["independentOf"].append("ORACLE_TESTS")
    elif change == "skip_rule":
        record["levels"]["programme"]["coverageSkip"]["rootNames"].append("linux-probe-kit")
    elif change == "key_order":
        return _serial(record, sort_keys=True), before
    elif change == "indent":
        return _serial(record, indent=2), before
    elif change == "no_newline":
        return _serial(record)[:-1], before
    elif change == "base_bytes":
        return _serial(record), before + b"\n"
    elif change == "base_version":
        base["version"] = 3
        return _serial(record), _serial(base)
    else:
        base_paths = _class(base, "CONTRACT_AND_SOURCE")["paths"]
        base_paths[-1], base_paths[-2] = base_paths[-2], base_paths[-1]
        return _serial(record), _serial(base)
    return _serial(record), before


@pytest.mark.parametrize("change", RECORD_CHANGES)
def test_the_records_change_is_exactly_the_version_and_the_kit_entry(change):
    raw, before = profile._verified(profile.RECORD_PATH), _before(profile.RECORD_PATH)
    profile.check_record(raw, before)
    assert _serial(_record()) == raw and _serial(_base()) == before
    paths = _class(_record(), "CONTRACT_AND_SOURCE")["paths"]
    assert paths[-2:] == [{"prefix": "release/"}, {"prefix": "linux-probe-kit/"}] and len(paths) == 9
    assert _record()["version"] == 3 and _base()["version"] == 2
    with pytest.raises(ValueError, match=re.escape("the record's change from version 2 is exactly the version and the "
                                                   "kit prefix entry after release/")):
        profile.check_record(*_record_mutant(change))


def _vector_parts():
    return (profile._verified(profile.VECTORS_PATH), _before(profile.VECTORS_PATH),
            _model().check(_record())["digest"], _model().check(_base())["digest"])


def _vectors_mutant(change):
    raw, before, record_digest, base_digest = _vector_parts()
    if change == "other_row":
        vectors = json.loads(raw)
        vectors["evidenceClass"] = "ACCEPTANCE"
        raw = _serial(vectors)
    elif change == "not_repinned":
        raw = before
    elif change == "wrong_digest":
        record_digest = record_digest[:-1] + ("0" if record_digest[-1] != "0" else "1")
    elif change == "same_digest":
        record_digest = base_digest
    elif change == "twice":
        before = before.replace(b'"DATA_CHECK_ONLY"', ('"' + base_digest + '"').encode("ascii"), 1)
    elif change == "base_digest":
        base_digest = base_digest[:-1] + ("0" if base_digest[-1] != "0" else "1")
    elif change == "extra_byte":
        raw = raw.replace(b'"DATA_CHECK_ONLY"', b'"DATA_CHECK_ONLY "', 1)
    else:
        raw = raw.decode("ascii")
    return raw, before, record_digest, base_digest


@pytest.mark.parametrize("change", ["other_row", "not_repinned", "wrong_digest", "same_digest", "twice", "base_digest",
                                    "extra_byte", "not_bytes"])
def test_the_vectors_only_change_is_the_repinned_record_digest(change):
    raw, before, record_digest, base_digest = _vector_parts()
    profile.check_vectors(raw, before, record_digest, base_digest)
    assert json.loads(raw)["recordDigest"] == record_digest != base_digest == json.loads(before)["recordDigest"]
    assert {key: value for key, value in json.loads(raw).items() if key != "recordDigest"} == {
        key: value for key, value in json.loads(before).items() if key != "recordDigest"}
    with pytest.raises(ValueError, match=re.escape("the vectors' only change is the re-pinned record digest")):
        profile.check_vectors(*_vectors_mutant(change))


# The unchanged model over version 3 -----------------------------------------------------------------------------------

def _gate_mutant(change):
    gate, base_gate = deepcopy(_model().check(_record())["gateMaterial"]), _gate()
    if change == "drop":
        gate.pop()
    elif change == "extra":
        gate.append({"exact": "README.md"})
    elif change == "replaced":
        gate[-1] = {"exact": "README.md"}
    elif change == "under_name":
        gate[-1] = {"under": "architecture/", "name": "REVIEW_BRIEF*.md"}
    elif change == "two_keys":
        gate[0] = dict(gate[0], prefix="x/")
    elif change == "not_dict":
        gate[0] = "AGENTS.md"
    elif change == "base_differs":
        base_gate = base_gate[:-1]
    elif change == "kit_gate":
        gate.append({"prefix": "linux-probe-kit/"})
        base_gate = base_gate + [{"prefix": "linux-probe-kit/"}]
    else:
        gate = tuple(gate)
    return gate, base_gate


@pytest.mark.parametrize("change", ["drop", "extra", "replaced", "under_name", "two_keys", "not_dict", "base_differs",
                                    "kit_gate", "not_list"])
def test_the_model_derives_version_2s_31_gate_entries_from_version_3(change):
    gate = _model().check(_record())["gateMaterial"]
    profile.check_gate_list(gate, _gate())
    assert gate == _gate() and len(gate) == 31 and {"prefix": "linux-probe-kit/"} not in gate
    assert _model().derive_gate_material(_record()) == gate
    with pytest.raises(ValueError, match=re.escape("the model derives version 2's 31 exact or prefix gate entries from "
                                                   "version 3")):
        profile.check_gate_list(*_gate_mutant(change))


def test_the_vectors_replay_over_version_3_with_the_base_counts():
    counts = profile._replays(_model(), _record(), json.loads(profile._verified(profile.VECTORS_PATH)))
    profile.check_replay(counts)
    assert counts == {"decisions": 44, "invariants": 31, "texts": 5, "paths": 23, "skip": 8, "prs": 9, "coverage": 2,
                      "requests": 10, "derived": 31, "consumerCases": 12}
    # The vectors pinned to version 2's digest do not replay over version 3: the model raises its own Mismatch.
    stale = profile._replays(_model(), _record(), json.loads(_before(profile.VECTORS_PATH)))
    assert stale is None
    for value in (stale, dict(counts, derived=32), {key: counts[key] for key in counts if key != "coverage"}, [], ()):
        with pytest.raises(ValueError, match=re.escape("the model replays the re-pinned vectors over version 3 with the "
                                                       "base's counts")):
            profile.check_replay(value)


KIT = ("linux-probe-kit/x is CONTRACT_AND_SOURCE, Linux-Probe-Kit/x no class, and a kit-only PR has approvers "
       "LANE_MONITOR and OWNER")


def _kit_parts(record=None):
    record = _record() if record is None else record
    model = _model()
    return ({path: model.resolve(record, path) for path in profile.KIT_PROBES},
            {path: model.resolve(_base(), path) for path in profile.KIT_PROBES},
            profile._approvers(record, model.resolve(record, profile.KIT_PATH)))


def _kit_mutant(change):
    if change == "spelled_upper":
        record = _record()
        _class(record, "CONTRACT_AND_SOURCE")["paths"][-1] = {"prefix": "Linux-Probe-Kit/"}
        return _kit_parts(record)
    if change == "not_added":
        return _kit_parts(_base())
    resolved, base_resolved, approvers = _kit_parts()
    if change == "unclassified":
        resolved[profile.KIT_PATH] = None
    elif change == "other_class":
        resolved[profile.KIT_PATH] = "REPOSITORY_ROOT"
    elif change == "case_variant":
        resolved[profile.KIT_CASE_VARIANT] = "CONTRACT_AND_SOURCE"
    elif change == "base_resolves":
        base_resolved[profile.KIT_PATH] = "CONTRACT_AND_SOURCE"
    elif change == "owner_only":
        approvers = ["OWNER"]
    elif change == "no_approvers":
        approvers = None
    else:
        approvers = ["OWNER", "LANE_MONITOR"]
    return resolved, base_resolved, approvers


@pytest.mark.parametrize("change", ["spelled_upper", "not_added", "unclassified", "other_class", "case_variant",
                                    "base_resolves", "owner_only", "no_approvers", "order"])
def test_the_kit_prefix_resolves_as_ruled_b_g3_2(change):
    """B-G3-2, with the unchanged model over version 3: linux-probe-kit/x -> CONTRACT_AND_SOURCE; Linux-Probe-Kit/x -> no
    class; a PR whose only changed path is under linux-probe-kit/ has approvers [LANE_MONITOR, OWNER]. The model's own
    pr_approvers agrees with the layer's one-path derivation."""
    resolved, base_resolved, approvers = _kit_parts()
    profile.check_kit(resolved, base_resolved, approvers)
    model, record = _model(), _record()
    assert resolved == {"linux-probe-kit/x": "CONTRACT_AND_SOURCE", "Linux-Probe-Kit/x": None}
    assert model.pr_approvers(record, ["linux-probe-kit/x"]) == approvers == ["LANE_MONITOR", "OWNER"]
    assert model.pr_approvers(record, ["linux-probe-kit/a.txt", "linux-probe-kit/b/c.py"]) == ["LANE_MONITOR", "OWNER"]
    assert model.pr_approvers(record, ["Linux-Probe-Kit/x"]) is None and model.pr_approvers(_base(), ["linux-probe-kit/x"]) is None
    for path in ("docs/linux-probe-kit/README.md", "architecture/probe-kit-scope/amendment.json",
                 "architecture/linux-probe-interface/binding.json"):
        assert model.resolve(record, path) == model.resolve(_base(), path) == "CONTRACT_AND_SOURCE", path
    assert model.resolve(record, "architecture/probe-kit-scope/review-round1.json") == "REVIEW_RECORD"
    assert model.resolve(record, "ci/linux-runner/build.py") == "GATE_CI"
    assert model.resolve(record, "docs/linux-runner/README.md") == "GATE_VERIFIER_DOCS"
    with pytest.raises(ValueError, match=re.escape(KIT)):
        profile.check_kit(*_kit_mutant(change))


# The registry (B-G3-1) ------------------------------------------------------------------------------------------------

REGISTRY_MESSAGE = "the registry is 260's with exactly the two MET-LIVE-004 entries appended, each pinning its brief"


def _registry_parts():
    raw = profile._verified(profile.REGISTRY_PATH)
    return raw, profile._undo_this_layer(profile.REGISTRY_PATH, raw), {
        path: profile._verified(path) for path in (profile.PACKET_BRIEF, profile.CONTRACT_BRIEF)}


def _registry_mutant(change):
    raw, base, briefs = _registry_parts()
    registry = json.loads(raw)
    if change == "base_bytes":
        base = base + b"\n"
    elif change == "brief_bytes":
        briefs = {**briefs, profile.CONTRACT_BRIEF: briefs[profile.CONTRACT_BRIEF] + b"\n"}
    elif change == "serialization":
        raw = _serial(registry, indent=2)
    elif change == "missing_entry":
        registry["briefs"].pop()
    elif change == "extra_entry":
        registry["briefs"].append(dict(registry["briefs"][-2], series="MET-LIVE-005/packet"))
    elif change == "entry_order":
        registry["briefs"][-1], registry["briefs"][-2] = registry["briefs"][-2], registry["briefs"][-1]
    elif change == "entry_digest":
        registry["briefs"][-1]["sha256"] = _flip(registry["briefs"][-1]["sha256"])
    elif change == "entry_version":
        registry["briefs"][-1]["version"] = 2
    elif change == "entry_path":
        registry["briefs"][-2]["path"] = "architecture/review-record/REVIEW_BRIEF_PACKET.md"
    elif change == "entry_series":
        registry["briefs"][-2]["series"] = "MET-LIVE-004/"
    elif change == "entry_kind":
        registry["briefs"][-1]["kind"] = "DESIGN"
    elif change == "entry_member":
        registry["briefs"][-1]["supersededAt"] = "2026-10-24T00:00:00+08:00"
    elif change == "base_entry":
        registry["briefs"][0]["version"] = 2
    elif change == "kinds":
        del registry["kinds"]["DESIGN"]
    else:
        registry["schemaVersion"] = "planeon.review-briefs/v2"
    if change not in ("base_bytes", "brief_bytes", "serialization"):
        raw = _serial(registry)
    return raw, base, briefs


@pytest.mark.parametrize("change", ["base_bytes", "brief_bytes", "serialization", "missing_entry", "extra_entry",
                                    "entry_order", "entry_digest", "entry_version", "entry_path", "entry_series",
                                    "entry_kind", "entry_member", "base_entry", "kinds", "schema"])
def test_the_registry_is_260s_with_exactly_the_two_met_live_004_entries(change):
    profile.check_registry(*_registry_parts())
    raw, base, briefs = _registry_parts()
    added = json.loads(raw)["briefs"][len(json.loads(base)["briefs"]):]
    assert [(entry["kind"], entry["series"], entry["path"]) for entry in added] == [
        ("PACKET", "MET-LIVE-004/packet", "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"),
        ("CONTRACT", "MET-LIVE-004/contract", "architecture/review-briefs/REVIEW_BRIEF_CONTRACT.md")]
    assert len(json.loads(raw)["briefs"]) == 8 and _serial(json.loads(raw)) == raw
    with pytest.raises(ValueError, match=re.escape(REGISTRY_MESSAGE)):
        profile.check_registry(*_registry_mutant(change))


# The oracle edit and its re-issued identity -------------------------------------------------------------------------

ORACLE_MESSAGE = ("the oracle file is the agent's edit, and the re-issued identity binds it with ruling KEEP by the lane "
                  "monitor")


def _oracle_mutant(change):
    identity_raw, oracle = profile._verified(profile.ORACLE_IDENTITY_PATH), profile._verified(profile.ORACLE_TEST)
    identity = json.loads(identity_raw)
    if change == "oracle_bytes":
        return identity_raw, oracle + b"\n"
    if change == "base_oracle":
        return identity_raw, _before(profile.ORACLE_TEST)
    if change == "identity_bytes":
        return identity_raw + b"\n", oracle
    if change == "base_identity":
        return _before(profile.ORACLE_IDENTITY_PATH), oracle
    if change == "not_bytes":
        return identity_raw.decode("utf-8"), oracle
    if change == "decision":
        identity["ruling"]["decision"] = "VOID"
    elif change == "by":
        identity["ruling"]["by"] = "OWNER"
    elif change == "ref":
        identity["ruling"]["ref"] = "MON-261-ORACLE-KEEP"
    elif change == "file_digest":
        identity["file"]["sha256"] = _flip(identity["file"]["sha256"])
    elif change == "file_path":
        identity["file"]["path"] = "tests/test_review_record_oracle.py"
    else:
        identity["schemaVersion"] = "planeon.oracle-identity/v2"
    return _serial(identity), oracle


@pytest.mark.parametrize("change", ["oracle_bytes", "base_oracle", "identity_bytes", "base_identity", "not_bytes",
                                    "decision", "by", "ref", "file_digest", "file_path", "schema"])
def test_the_reissued_identity_binds_the_edited_oracle_file_with_keep(change):
    identity_raw, oracle = profile._verified(profile.ORACLE_IDENTITY_PATH), profile._verified(profile.ORACLE_TEST)
    profile.check_oracle(identity_raw, oracle)
    identity = json.loads(identity_raw)
    assert identity["file"] == {"path": "tests/test_evolution_surface_oracle.py", "sha256": profile.digest(oracle)}
    assert identity["ruling"] == {"decision": "KEEP", "by": "LANE_MONITOR",
                                  "ref": "MON-261-ORACLE-KEEP; MON-261-ORACLE-SLIPS", "date": "2026-10-23"}
    with pytest.raises(ValueError, match=re.escape(ORACLE_MESSAGE)):
        profile.check_oracle(*_oracle_mutant(change))


def _edit_mutant(change):
    raw, before = profile._verified(profile.ORACLE_TEST), _before(profile.ORACLE_TEST)
    lines = raw.splitlines(keepends=True)
    marked = [n for n, line in enumerate(lines) if b"MET-GOV-003" in line]
    if change == "changed_line":
        n = [n for n in range(len(lines)) if n not in marked and lines[n].strip()][-1]
        lines[n] = lines[n].replace(b"\n", b" \n")
    elif change == "removed_line":
        del lines[[n for n in range(len(lines)) if n not in marked and lines[n].strip()][-1]]
    elif change == "third_line":
        lines.append(b"# MET-GOV-003: one more line\n")
    elif change == "one_line":
        del lines[marked[0]]
    elif change == "unmarked_line":
        lines.insert(marked[0], b"# record version 3\n")
    elif change == "base_marked":
        return raw, before + b"# MET-GOV-003\n"
    else:
        return raw.decode("utf-8"), before
    return b"".join(lines), before


@pytest.mark.parametrize("change", ["changed_line", "removed_line", "third_line", "one_line", "unmarked_line",
                                    "base_marked", "not_bytes"])
def test_the_oracle_edit_is_two_added_marked_lines(change):
    raw, before = profile._verified(profile.ORACLE_TEST), _before(profile.ORACLE_TEST)
    profile.check_oracle_edit(raw, before)
    added = [line for line in raw.splitlines() if b"MET-GOV-003" in line]
    assert len(added) == 2 and any(b'P("linux-probe-kit/")' in line for line in added)
    assert len(raw.splitlines()) == len(before.splitlines()) + 2
    with pytest.raises(ValueError, match=re.escape("the oracle edit adds exactly two MET-GOV-003 lines to 260's oracle "
                                                   "file")):
        profile.check_oracle_edit(*_edit_mutant(change))


# The derived gate check (B-G3-1) --------------------------------------------------------------------------------------

GATE_HITS_MESSAGE = ("the gate paths among the changed files are exactly the record, vectors, README, oracle identity "
                     "and registry")


def _hits_mutant(change):
    changed = _changed()
    if change == "no_registry":
        changed.remove(profile.REGISTRY_PATH)
    elif change == "no_identity":
        changed.remove(profile.ORACLE_IDENTITY_PATH)
    elif change == "no_readme":
        changed.remove(profile.README_PATH)
    elif change == "model":
        changed = sorted(changed + [profile.SURFACE_MODEL])
    elif change == "in_tree_test":
        changed = sorted(changed + ["tests/test_review_records_in_tree.py"])
    elif change == "gate_prefix":
        changed = sorted(changed + ["ci/linux-runner/runner.py"])
    elif change == "case_variant":
        changed = sorted(changed + ["Architecture/Review-Record/README.md"])
    elif change == "review_record_file":
        changed = sorted(changed + ["architecture/review-record/README.md"])
    else:
        changed.reverse()
    return _gate(), changed


@pytest.mark.parametrize("change", ["no_registry", "no_identity", "no_readme", "model", "in_tree_test", "gate_prefix",
                                    "case_variant", "review_record_file", "unsorted"])
def test_the_gate_paths_among_the_changed_files_are_exactly_the_five(change):
    gate, changed = _gate(), _changed()
    profile.check_gate_hits(gate, changed)
    assert profile.gate_paths(gate, changed) == sorted(profile.GATE_HITS)
    assert profile.ORACLE_TEST in changed and profile.gate_paths(gate, [profile.ORACLE_TEST]) == []
    # The packet is gate material: the model's own approvers of its changed files are the owner alone.
    assert _model().pr_approvers(_base(), changed) == _model().pr_approvers(_record(), changed) == ["OWNER"]
    with pytest.raises(ValueError, match=re.escape(GATE_HITS_MESSAGE)):
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

SEMANTIC_FUNCTIONS = {"_era_bytes", "_verified", "check_freeze", "check_new_files", "check_private", "check_adopted",
                      "check_before", "check_record", "check_vectors", "check_gate_list", "check_replay", "check_kit",
                      "check_registry", "check_oracle", "check_oracle_edit", "check_gate_hits"}
CHECK_TESTS = {
    "MET-GOV-003 reviewed bytes are bound: ": "test_a_path_outside_the_era_is_refused_before_it_is_read",
    "unreviewed LINUX-PROBE-KIT-GATE source: ": "test_every_era_file_is_bound_by_digest",
    FREEZE: "test_the_freeze_refuses_every_other_change",
    "this packet adds exactly its layer test": "test_the_packet_adds_exactly_its_layer_test",
    "no absolute local path in a contract file this packet changes: ":
        "test_a_changed_contract_file_holds_no_absolute_local_path",
    "the record, vectors and README are the adopted c3 bytes: ":
        "test_the_record_vectors_and_readme_are_the_adopted_c3_bytes",
    "260's merged bytes are bound: ": "test_260s_merged_bytes_are_bound",
    "the record's change from version 2 is exactly the version and the kit prefix entry after release/":
        "test_the_records_change_is_exactly_the_version_and_the_kit_entry",
    "the vectors' only change is the re-pinned record digest":
        "test_the_vectors_only_change_is_the_repinned_record_digest",
    "the model derives version 2's 31 exact or prefix gate entries from version 3":
        "test_the_model_derives_version_2s_31_gate_entries_from_version_3",
    "the model replays the re-pinned vectors over version 3 with the base's counts":
        "test_the_vectors_replay_over_version_3_with_the_base_counts",
    KIT: "test_the_kit_prefix_resolves_as_ruled_b_g3_2",
    REGISTRY_MESSAGE: "test_the_registry_is_260s_with_exactly_the_two_met_live_004_entries",
    ORACLE_MESSAGE: "test_the_reissued_identity_binds_the_edited_oracle_file_with_keep",
    "the oracle edit adds exactly two MET-GOV-003 lines to 260's oracle file":
        "test_the_oracle_edit_is_two_added_marked_lines",
    GATE_HITS_MESSAGE: "test_the_gate_paths_among_the_changed_files_are_exactly_the_five",
    "unreviewed current source: ": "test_the_canonical_check_reads_this_eras_bytes",
    "canonical byte-minimal inverse hunks: ": "test_whole_line_hunks_are_refused_where_canonical_ones_differ"}
NAMED_MESSAGES = {FREEZE: "FREEZE", KIT: "KIT", REGISTRY_MESSAGE: "REGISTRY_MESSAGE", ORACLE_MESSAGE: "ORACLE_MESSAGE",
                  GATE_HITS_MESSAGE: "GATE_HITS_MESSAGE"}


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
