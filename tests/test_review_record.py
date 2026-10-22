"""Exact source lineage for MET-GOV-002; the review record v2 contract: the head keeps the full fan-in (8 own and 70 predecessor routes, every catalog walk and round trip, the full payload loop), and the semantic check (the freeze, the files added, the adoption with its v2 review rounds and identities, the model replaying its vectors from this era's bytes, the evolution surface record v2 and the canonical hunks) has a failing case for every refusal, each on plain data. The candidate's own tests follow (the model replays every vector; the schemas state its closed members; the published registry and frozen list load; check_tree on synthetic trees; privacy by digest only)."""
import ast
import json
from copy import deepcopy
import os
import re
import stat
import types
from pathlib import Path
from types import MappingProxyType

import pytest

from scripts import validate_review_record as profile
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
    assert len(current) == 259 and len(accepted) == 258
    assert set(accepted) == set(current) - {profile.NEW_PACKET}
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


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "pod_old", "evs_old", "e9_old", "ccomp_old", "i6v4_old", "dcap_old", "np5_old", "lrp_old", "wpa3_old", "cfp3_old", "sol_old", "mx6_old", "np4_old", "tcv1_old", "wpa2_old", "la2_old", "i5v4_old", "cdh_old", "cfp2_old", "smx_old", "phr_old", "sv4_old", "hs43_old", "rav3_old", "deadlines_old", "events_old", "filters_old", "loop_old", "manifest_old", "ledger_old", "adoption_old", "amendment_old", "bprofile_old", "mprofile_old", "eprofile_old", "lprofile_old", "fprofile_old", "oprofile_old", "uprofile_old", "jprofile_old", "kprofile_old", "tprofile_old", "zprofile_old", "yprofile_old", "xprofile_old", "pprofile_old", "aprofile_old", "vprofile_old", "cprofile_old", "qprofile_old", "hprofile_old", "dprofile_old", "sprofile_old", "wprofile_old", "rprofile_old", "gprofile_old", "iprofile_old", "nprofile_old", "resolution_old", "account_old", "canary_old", "isolated_old", "portable_old", "proof_old", "recheck_old", "verifier_old", "linux_old", "performance_old", "runner_old", "roadmap_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = profile.historical_bytes(path, raw) if route in ("current_test", "old_bytes") else None
    current_packets = packets() if route in ("catalog", "payloads") else None
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
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
    with pytest.raises(ValueError, match="review record history authority digest"):
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
    assert len(profile.historical_catalog(current)) == 258


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
    assert len(profile.historical_catalog(current)) == 258
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
    assert len(rules) == 259 and len(parsed) == 258
    assert profile._packet_rules() is rules and len(parsed) == 258
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
    with pytest.raises(ValueError, match="review record history authority digest"):
        profile.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = packets()
    profile.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "review-record-authority.json").write_bytes(
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
    with pytest.raises(ValueError, match="review record validator drift"):
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
    for module in (profile, pod, evs, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner):
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
    expected = {module.__name__: 1 for module in (profile, pod, evs, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner)}
    if route == "current_test":
        # The forward route reads this layer's newest bytes and then projects them forward once more.
        assert all(counts[name] >= 1 for name in expected) and set(counts) == set(expected)
    else:
        assert counts == expected


# MET-GOV-002 (REVIEW-RECORD-V2): this era's check, and a failing case for every check. Every mutant below is applied to
# plain data handed to the layer's pure checks: nothing in the layer or the library is patched or swapped.


def _status():
    return json.loads(profile._verified(profile.STATUS_PATH))


def _era_models():
    return profile.era_models()


def test_every_era_file_is_bound_by_digest():
    for path in profile.ERA_SHA256:
        assert profile.digest(profile._verified(path)) == profile.ERA_SHA256[path]
    path = profile.STATUS_PATH
    raw = profile._verified(path)
    with pytest.raises(ValueError, match="unreviewed REVIEW-RECORD-V2 source: " + re.escape(path)):
        profile._era_bytes(path, raw + b"\n")
    with pytest.raises(ValueError, match="MET-GOV-002 reviewed bytes are bound"):
        profile._verified("README.md")
    with pytest.raises(ValueError, match="MET-GOV-002 reviewed bytes are bound"):
        profile._era_bytes(None, raw)


def test_the_era_holds_the_new_files_and_the_three_surface_files():
    assert set(profile.ERA_SHA256) == set(profile.NEW_FILES) | set(profile.SURFACE_CHANGED) | {profile.SURFACE_MODEL}
    assert len(profile.RECORDS) == len(profile.IDENTITIES) == profile.ROUNDS
    assert profile.ROUNDS == len(profile.ROUND_ROWS)


@pytest.mark.parametrize("changed, added, message", [
    (["architecture/chain-compaction/README.md"], [], "under architecture/ only MET-GOV-001"),
    (["scripts/evolution_surface.py"], [], "no model changes"),
    (["scripts/review_record.py"], [], "no model changes"),
    ([], ["architecture/other/README.md"], "only the contract's directory is added"),
    ([None], [], "no model changes"),
    ([], [3], "only the contract's directory is added"),
    (["scripts/chain_identity.py"], [], "no model changes"),
    (["scripts/policy_observation_digests.py"], [], "no model changes"),
    (["scripts/validate_x.txt"], [], "no model changes"),
    (["scripts/validate_x/y.py"], [], "no model changes"),
    (["tests/conftest.py"], [], "no conftest change"),
    (["conftest.py"], [], "no conftest change"),
])
def test_the_freeze_refuses_other_architecture_and_model_changes(changed, added, message):
    profile.check_freeze(list(profile.SURFACE_CHANGED) + ["scripts/validate_chain_compaction.py"],
                         list(profile.NEW_FILES) + ["tests/test_review_record.py"])
    with pytest.raises(ValueError, match=message):
        profile.check_freeze(changed, added)


@pytest.mark.parametrize("change", ["missing", "extra", "changed_too", "duplicate"])
def test_the_new_files_are_new_and_each_once(change):
    added = list(profile.NEW_FILES) + ["tests/test_review_record.py"]
    changed = list(profile.SURFACE_CHANGED)
    profile.check_new_files(added, changed)
    if change == "missing":
        added.remove(profile.STATUS_PATH)
    elif change == "extra":
        added.append(profile.CONTRACT_DIR + "/extra.json")
    elif change == "changed_too":
        changed.append(profile.MODEL_PATH)
    else:
        added = added + [profile.MODEL_PATH]
        changed.append(profile.MODEL_PATH)
    with pytest.raises(ValueError, match="new in this packet, each once"):
        profile.check_new_files(added, changed)


@pytest.mark.parametrize("change, message", [
    ("extra", "holds exactly its files"), ("missing", "holds exactly its files"),
    ("executable", "holds exactly its files"), ("link", "holds exactly its files"),
    ("directory_link", "the contract directory is a directory, not a link")])
def test_the_contract_directory_is_closed_and_every_file_is_mode_100644(change, message):
    mode, tree = profile.reviewed_mode(profile.CONTRACT_DIR), profile.reviewed_tree(profile.CONTRACT_DIR)
    assert sorted(tree) == sorted(profile.DIRECTORY_FILES) and stat.S_ISDIR(mode)
    profile.check_contract_tree(mode, tree)
    tree = dict(tree)
    if change == "extra":
        tree[profile.CONTRACT_DIR + "/round6"] = stat.S_IFDIR | 0o755
    elif change == "missing":
        del tree[profile.RECORDS[0]]
    elif change == "executable":
        tree[profile.STATUS_PATH] = stat.S_IFREG | 0o755
    elif change == "link":
        tree[profile.IDENTITIES[0]] = stat.S_IFLNK | 0o777
    else:
        mode = stat.S_IFLNK | 0o777
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.check_contract_tree(mode, tree)


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


@pytest.mark.parametrize("change", ["schema", "work_item", "packet", "slot", "slot_text", "status", "base", "series",
                                    "commit", "subject_order", "adoption", "owner_decision", "owner_order", "non_claim",
                                    "extra_key", "missing_key", "key_order"])
def test_the_status_is_closed_and_records_the_adoption(change):
    status = _status()
    profile.check_status(status)
    if change == "schema":
        status["schemaVersion"] = "planeon.internal.evolution-surface-status/v1"
    elif change == "work_item":
        status["workItem"] = "REVIEW-RECORD-V2"
    elif change == "packet":
        status["packet"] = "MET-GOV-001"
    elif change == "slot":
        status["slot"] = 258
    elif change == "slot_text":
        status["slot"] = "259"
    elif change == "status":
        status["status"] = "CONTRACT_CANDIDATE"
    elif change == "base":
        status["baseMain"] = "30f41e6f5fb2ffdcef7d72e9e90825e66a17cca7"
    elif change == "series":
        status["series"] = "MET-GOV-002/design"
    elif change == "commit":
        status["adoptedSubject"]["commit"] = "0" * 40
    elif change == "subject_order":
        status["adoptedSubject"] = dict(reversed(list(status["adoptedSubject"].items())))
    elif change == "adoption":
        status["adoption"]["decision"] = status["adoption"]["decision"].replace("(a)", "(b)")
    elif change == "owner_decision":
        status["ownerDecisions"][0] = status["ownerDecisions"][0].replace("(Recommended)", "")
    elif change == "owner_order":
        status["ownerDecisions"].reverse()
    elif change == "non_claim":
        status["nonClaims"].pop()
    elif change == "extra_key":
        status["extra"] = 1
    elif change == "missing_key":
        del status["nonClaims"]
    else:
        status["packet"] = status.pop("packet")
    with pytest.raises(ValueError, match="adopted REVIEW-RECORD-V2 status"):
        profile.check_status(status)


@pytest.mark.parametrize("change", ["digest", "missing", "extra", "unsorted"])
def test_the_status_names_every_adopted_file_by_its_reviewed_digest(change):
    status = _status()
    profile.check_subject(status)
    files = status["reviewedFiles"]
    if change == "digest":
        files[profile.MODEL_PATH] = "0" * 64
    elif change == "missing":
        del files[profile.LEGACY_PATH]
    elif change == "extra":
        files["scripts/other.py"] = "0" * 64
    else:
        status["reviewedFiles"] = dict(reversed(list(files.items())))
    with pytest.raises(ValueError, match="status.json names every adopted file by its reviewed digest"):
        profile.check_subject(status)


@pytest.mark.parametrize("path", [p for p in profile.SUBJECT if p != profile.README_PATH])
def test_the_contract_files_are_the_final_rounds_reviewed_bytes(path):
    raw = profile._verified(path)
    profile.check_adopted_file(path, raw)
    for changed in (raw + b"\n", raw.replace(b"\n", b"\r\n", 1), None):
        with pytest.raises(ValueError, match=re.escape("the contract files are the final round's reviewed bytes: "
                                                       + path)):
            profile.check_adopted_file(path, changed)
    with pytest.raises(ValueError, match="reviewed bytes: " + re.escape(profile.README_PATH)):
        profile.check_adopted_file(profile.README_PATH, profile._verified(profile.README_PATH))


@pytest.mark.parametrize("change", ["path", "replaced", "with", "reviewed_digest", "adopted_digest", "readme_bytes",
                                    "old_line_back", "edited_elsewhere", "extra_key", "key_order"])
def test_the_readme_status_line_is_the_one_adoption_edit(change):
    edit, readme = _status()["adoptionEdit"], profile._verified(profile.README_PATH)
    profile.check_adoption_edit(edit, readme)
    if change == "path":
        edit["path"] = profile.BRIEF_PATH
    elif change == "replaced":
        edit["replaced"] = edit["replaced"].replace("Not adopted.", "Adopted.")
    elif change == "with":
        edit["with"] = edit["with"].replace("ADOPTED_", "")
    elif change == "reviewed_digest":
        edit["reviewedSha256"] = edit["adoptedSha256"]
    elif change == "adopted_digest":
        edit["adoptedSha256"] = edit["reviewedSha256"]
    elif change == "readme_bytes":
        readme = readme + b"\n"
    elif change == "old_line_back":
        readme = readme + edit["replaced"].encode("utf-8")
    elif change == "edited_elsewhere":
        assert readme.count(b"## The digest rule\n") == 1
        readme = readme.replace(b"## The digest rule\n", b"## The digest rules\n")
        edit["adoptedSha256"] = profile.digest(readme)
    elif change == "extra_key":
        edit["note"] = "x"
    else:
        edit["path"] = edit.pop("path")
    with pytest.raises(ValueError, match="the README's status line is the one adoption edit"):
        profile.check_adoption_edit(edit, readme)


ROUND_CHANGES = ["record_bytes", "record_digest", "identity_digest", "record_path", "identity_path", "verdict",
                 "findings", "ruling", "subject", "base", "row_key", "key_order", "record_verdict", "record_finding",
                 "identity_ruling"]


@pytest.mark.parametrize("change", ROUND_CHANGES)
@pytest.mark.parametrize("number", range(1, profile.ROUNDS + 1))
def test_each_round_is_bound_to_its_record_and_identity(number, change):
    row = _status()["rounds"][number - 1]
    record_raw = profile._verified(profile.RECORDS[number - 1])
    identity_raw = profile._verified(profile.IDENTITIES[number - 1])
    profile.check_round(number, row, record_raw, identity_raw)
    if change == "record_bytes":
        record_raw = record_raw + b" "
    elif change == "record_digest":
        row["recordSha256"] = "0" * 64
    elif change == "identity_digest":
        row["identitySha256"] = row["recordSha256"]
    elif change == "record_path":
        row["record"] = profile.IDENTITIES[number - 1]
    elif change == "identity_path":
        row["identity"] = profile.RECORDS[number - 1]
    elif change == "verdict":
        row["verdict"] = "PASS_FOR_SOURCE_PUBLICATION"
    elif change == "findings":
        row["findings"] = row["findings"] + ["RR2C9-1"]
    elif change == "ruling":
        row["ruling"] = "MON-X"
    elif change == "subject":
        row["subject"] = dict(row["subject"], tree="0" * 40)
    elif change == "base":
        if "base" in row:
            del row["base"]
        else:
            row["base"] = dict(row["subject"])
    elif change == "row_key":
        row["note"] = "x"
    elif change == "key_order":
        row["round"] = row.pop("round")
    elif change == "record_verdict":
        record = json.loads(record_raw)
        record["verdict"] = "PASS_FOR_SOURCE_PUBLICATION"
        record_raw = json.dumps(record).encode("utf-8")
        row["recordSha256"] = profile.digest(record_raw)
    elif change == "record_finding":
        record = json.loads(record_raw)
        record["findings"] = record["findings"][1:] if record["findings"] else [{"id": "X"}]
        record_raw = json.dumps(record).encode("utf-8")
        row["recordSha256"] = profile.digest(record_raw)
    else:
        identity = json.loads(identity_raw)
        identity["ruling"]["ref"] = "MON-X"
        identity_raw = json.dumps(identity).encode("utf-8")
        row["identitySha256"] = profile.digest(identity_raw)
    with pytest.raises(ValueError, match="round %d is bound to its record and identity" % number):
        profile.check_round(number, row, record_raw, identity_raw)


def _rebound(records, identities, number, record_change=None, identity_change=None):
    """Round `number` changed, with its identity re-bound to the changed record's bytes, so that only the rule the change
    targets can fail (packet review r1, P1-3)."""
    records, identities = list(records), list(identities)
    path, raw = records[number - 1]
    record = json.loads(raw)
    if record_change:
        record_change(record)
    raw = json.dumps(record).encode("utf-8")
    identity = json.loads(identities[number - 1][1])
    identity["record"]["sha256"] = profile.digest(raw)
    if identity_change:
        identity_change(identity)
    records[number - 1] = (path, raw)
    identities[number - 1] = (identities[number - 1][0], json.dumps(identity).encode("utf-8"))
    return records, identities


def _set(*steps):
    def change(value):
        for keys, item in steps:
            node = value
            for key in keys[:-1]:
                node = node[key]
            if item is _DROP:
                del node[keys[-1]]
            else:
                node[keys[-1]] = item
    return change


def _review_by_an_author(identity):
    """The reviewer becomes an author who is not the operator, so only the reviewer-not-author rule can fail (packet
    review r2, P2-1)."""
    authors = [agent for agent in identity["author"]["agentIds"] if agent != identity["operator"]["agentId"]]
    assert authors
    identity["reviewer"]["agentId"] = authors[0]


_DROP = object()
SERIES_CHANGES = {
    # each rule of _series_holds and _counting, one failing case each, the other bindings kept
    "record_path": lambda r, i, reg: ([(profile.IDENTITIES[0], r[0][1])] + r[1:], i, reg),
    "identity_path": lambda r, i, reg: (r, [(profile.RECORDS[0], i[0][1])] + i[1:], reg),
    "series": lambda r, i, reg: _rebound(r, i, 2, _set((["series"], "MET-GOV-002/other"))) + (reg,),
    "round": lambda r, i, reg: _rebound(r, i, 2, _set((["round"], 7))) + (reg,),
    "kind": lambda r, i, reg: _rebound(r, i, 2, _set((["kind"], "PACKET"))) + (reg,),
    "verdict_unknown": lambda r, i, reg: _rebound(r, i, 2, _set((["verdict"], "PASS_FOR_BUILD"))) + (reg,),
    "binding": lambda r, i, reg: (r, _rebound(r, i, 2, None, _set((["record", "sha256"], "0" * 64)))[1], reg),
    "brief": lambda r, i, reg: _rebound(r, i, 2, _set((["briefSha256"], "0" * 64)), _set((["briefSha256"], "0" * 64))) + (reg,),
    "brief_mismatch": lambda r, i, reg: _rebound(r, i, 2, None, _set((["briefSha256"], "0" * 64))) + (reg,),
    "subject": lambda r, i, reg: _rebound(r, i, 2, None, _set((["subject", "tree"], "0" * 40))) + (reg,),
    "base_identity": lambda r, i, reg: _rebound(r, i, 2, None, _set((["base", "tree"], "0" * 40))) + (reg,),
    "base_chain": lambda r, i, reg: _rebound(r, i, 3, _set((["base", "tree"], "0" * 40)),
                                             _set((["base", "tree"], "0" * 40))) + (reg,),
    "full_round_late": lambda r, i, reg: _rebound(r, i, 3, _set((["base"], _DROP)), _set((["base"], _DROP))) + (reg,),
    "ruling_pending": lambda r, i, reg: _rebound(r, i, 2, None, _set((["ruling"], {"decision": "PENDING"}))) + (reg,),
    "ruling_keep_without_ref": lambda r, i, reg: _rebound(r, i, 2, None, _set((["ruling", "ref"], _DROP))) + (reg,),
    "ruling_keep_without_by": lambda r, i, reg: _rebound(r, i, 2, None, _set((["ruling", "by"], _DROP))) + (reg,),
    "ruling_keep_without_date": lambda r, i, reg: _rebound(r, i, 2, None, _set((["ruling", "date"], _DROP))) + (reg,),
    "ruling_none_needed_with_disclosure": lambda r, i, reg: _rebound(
        r, i, 2, None, _set((["ruling"], {"decision": "NONE_NEEDED"}))) + (reg,),
    "ruling_none_needed_with_interruption": lambda r, i, reg: _rebound(
        r, i, 2, _set((["disclosures"], [])), _set((["ruling"], {"decision": "NONE_NEEDED"}),
                                                   (["interruptions"], ["stopped once"]))) + (reg,),
    "ruling_none_needed_with_relay": lambda r, i, reg: _rebound(
        r, i, 2, _set((["disclosures"], [])), _set((["ruling"], {"decision": "NONE_NEEDED"}),
                                                   (["operatorRelays"], ["relayed once"]))) + (reg,),
    "self_review": lambda r, i, reg: _rebound(r, i, 1, None, lambda v: v["reviewer"].__setitem__(
        "agentId", v["operator"]["agentId"])) + (reg,),
    "author_review": lambda r, i, reg: _rebound(r, i, 1, None, _review_by_an_author) + (reg,),
    "final_verdict": lambda r, i, reg: _rebound(r, i, profile.ROUNDS, _set((["verdict"], "CHANGES_REQUIRED"))) + (reg,),
    "final_subject": lambda r, i, reg: _rebound(r, i, profile.ROUNDS, _set((["subject", "tree"], "0" * 40)),
                                                _set((["subject", "tree"], "0" * 40))) + (reg,),
    "missing_round": lambda r, i, reg: (r[:-1], i[:-1], reg),
    "extra_identity": lambda r, i, reg: (r, i + i[-1:], reg),
    "registry_brief": lambda r, i, reg: (r, i, json.dumps(dict(json.loads(reg), briefs=[
        b for b in json.loads(reg)["briefs"] if b["series"] != profile.SERIES])).encode("utf-8")),
    "registry_brief_superseded": lambda r, i, reg: (r, i, json.dumps(dict(json.loads(reg), briefs=[
        dict(b, supersededAt="2026-10-22T00:00:00Z") if b["series"] == profile.SERIES else b
        for b in json.loads(reg)["briefs"]])).encode("utf-8")),
}


def test_a_none_needed_round_with_no_disclosure_interruption_or_relay_holds():
    """The NONE_NEEDED cases' base: round 2 with its disclosures cleared and a NONE_NEEDED ruling holds, so each case
    fails only on the interruption or relay it adds (packet review r2, P2-2)."""
    records = [(path, profile._verified(path)) for path in profile.RECORDS]
    identities = [(path, profile._verified(path)) for path in profile.IDENTITIES]
    identity = json.loads(identities[1][1])
    assert identity["interruptions"] == [] and identity["operatorRelays"] == []
    profile.check_series(*_rebound(records, identities, 2, _set((["disclosures"], [])),
                                   _set((["ruling"], {"decision": "NONE_NEEDED"}))),
                         profile._verified(profile.REGISTRY_PATH))


@pytest.mark.parametrize("change", sorted(SERIES_CHANGES))
def test_the_rounds_form_one_valid_series_ending_in_adoption(change):
    records = [(path, profile._verified(path)) for path in profile.RECORDS]
    identities = [(path, profile._verified(path)) for path in profile.IDENTITIES]
    registry = profile._verified(profile.REGISTRY_PATH)
    profile.check_series(records, identities, registry)
    # The re-binding alone changes nothing a rule checks, so the unchanged series still holds after it.
    profile.check_series(*_rebound(records, identities, 2), registry)
    records, identities, registry = SERIES_CHANGES[change](records, identities, registry)
    with pytest.raises(ValueError, match="the rounds form one valid series"):
        profile.check_series(records, identities, registry)


def test_the_model_replays_its_vectors_and_a_changed_vector_is_refused():
    model = _era_models()[0]
    vectors = json.loads(profile._verified(profile.VECTORS_PATH))
    profile.check_vector_replay(model, vectors)
    vectors["reviews"][0]["expect"] = "SHAPE"
    with pytest.raises(ValueError, match="the model replays its vectors with no mismatch"):
        profile.check_vector_replay(model, vectors)


@pytest.mark.parametrize("change", ["brief_bytes", "registry_entry", "registry_shape"])
def test_the_registry_pins_the_published_brief(change):
    raw, brief = profile._verified(profile.REGISTRY_PATH), profile._verified(profile.BRIEF_PATH)
    profile.check_registry(raw, brief)
    if change == "brief_bytes":
        brief = brief + b"\n"
    elif change == "registry_entry":
        value = json.loads(raw)
        value["briefs"][0]["version"] = 2
        value["briefs"][0]["supersedes"] = "0" * 64
        raw = json.dumps(value).encode("utf-8")
    else:
        raw = raw + b"x"
    with pytest.raises(ValueError, match="the registry pins the published brief"):
        profile.check_registry(raw, brief)


@pytest.mark.parametrize("change", ["base", "records", "oracles", "shape"])
def test_the_frozen_list_was_derived_at_this_base_with_the_builders_counts(change):
    # Synthetic lists only: the published list is loaded by the layer itself, never inspected here.
    model = _era_models()[0]
    profile.check_legacy(profile._verified(profile.LEGACY_PATH))
    entries = [{"path": "architecture/x%03d/review-round1.json" % n, "sha256": "0" * 64}
               for n in range(profile.LEGACY_RECORDS)]
    oracles = [{"path": "tests/test_x%d_oracle.py" % n, "sha256": "0" * 64} for n in range(profile.LEGACY_ORACLES)]
    value = {"schemaVersion": model.LEGACY_SCHEMA, "baseCommit": profile.BASE_COMMIT, "entries": entries,
             "oracleTests": oracles}
    profile.check_legacy(json.dumps(value).encode("utf-8"))
    if change == "base":
        value["baseCommit"] = "30f41e6f5fb2ffdcef7d72e9e90825e66a17cca7"
    elif change == "records":
        value["entries"] = entries[:-1]
    elif change == "oracles":
        value["oracleTests"] = oracles[:-1]
    else:
        value["oracleTests"] = [o["path"] for o in oracles]
    with pytest.raises(ValueError, match="the frozen list was derived at this packet's base"):
        profile.check_legacy(json.dumps(value).encode("utf-8"))


@pytest.mark.parametrize("change", ["version", "class", "vectors"])
def test_the_evolution_surface_record_v2_derives_31_entries(change):
    es = _era_models()[1]
    record = es.load(profile._verified(profile.SURFACE_RECORD))
    vectors = json.loads(profile._verified(profile.SURFACE_VECTORS))
    profile.check_surface(es, record, vectors)
    if change == "version":
        record["version"] = 1
    elif change == "class":
        classes = record["levels"]["programme"]["classes"]
        gate = next(c for c in classes if c["id"] == "GATE_REVIEW_PROCESS")
        gate["paths"] = gate["paths"][:-1]
    else:
        vectors["recordDigest"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="the evolution surface record v2 derives 31 gate-material entries"):
        profile.check_surface(es, record, vectors)


def test_the_era_models_are_executed_from_verified_bytes():
    model, es = _era_models()
    assert model.__name__ == "_met_gov_002_review_record" and es.__name__ == "_met_gov_002_evolution_surface"
    assert model.NAME_TOKEN_SHA256 == {} and model.REVIEW_CODES[0] == "NO_IDENTITY"


# The candidate's own tests (MET-GOV-002 contract, as the adoption commit holds them) ------------------------------------
import hashlib
import json
from pathlib import Path

import pytest

from scripts import evolution_surface as es
from scripts import review_record as rr

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "architecture/review-record"
VECTORS = json.loads((HERE / "vectors.json").read_bytes())
BASES = VECTORS["bases"]
REGISTRY = rr.load_registry(BASES["registry"])
SCHEMAS = {name: json.loads((ROOT / "schemas" / ("%s.schema.json" % name)).read_bytes())
           for name in ("review-record", "review-identity", "oracle-identity", "review-briefs")}


def test_every_vector_replays():
    counts = rr.replay(VECTORS)
    assert counts == {"reviews": 62, "series": 10, "oracles": 10, "prOracles": 5, "merges": 15, "registries": 13,
                      "legacy": 7, "trees": 18, "privacy": 5}


def test_the_tree_vectors_reach_every_tree_code_and_the_tree_rules():
    reached = {row["expect"] for row in VECTORS["trees"]} - {None}
    assert set(rr.TREE_CODES) <= reached
    assert reached == {"LEGACY_CHANGED", "NO_IDENTITY", "ORACLE_MISSING", "ORACLE_DIGEST", "SHAPE", "SERIES_FORK",
                       "PRIVACY"}


def test_the_schemas_accept_each_model_only_shape_case():
    # RR2C1-3: the README lists what the model refuses as SHAPE beyond the schemas; each such row is pinned here.
    jsonschema = pytest.importorskip("jsonschema")
    rows = [row for row in VECTORS["reviews"] if row.get("modelOnly")]
    assert len(rows) == 4
    record_v = jsonschema.Draft202012Validator(SCHEMAS["review-record"])
    identity_v = jsonschema.Draft202012Validator(SCHEMAS["review-identity"])
    for row in rows:
        record = rr.mutate(BASES["record"], row["record"]["mutate"])
        identity = rr.mutate(BASES["identity"], row["identity"]["mutate"])
        identity["record"] = {"path": row["recordPath"], "sha256": rr.file_sha256(rr.serialize(record))}
        assert record_v.is_valid(json.loads(json.dumps(record))), row["id"]
        assert identity_v.is_valid(json.loads(json.dumps(identity))), row["id"]
        assert row["expect"] == "SHAPE"


def test_the_schemas_reject_each_schema_agrees_case_as_the_model_does():
    # RR2C2-2: year 0000 and integers of 2^53 are refused by the schemas and the model alike.
    jsonschema = pytest.importorskip("jsonschema")
    reviews = [row for row in VECTORS["reviews"] if row.get("schemaAgrees")]
    registries = [row for row in VECTORS["registries"] if row.get("schemaAgrees")]
    assert len(reviews) == 2 and len(registries) == 1
    record_v = jsonschema.Draft202012Validator(SCHEMAS["review-record"])
    identity_v = jsonschema.Draft202012Validator(SCHEMAS["review-identity"])
    briefs_v = jsonschema.Draft202012Validator(SCHEMAS["review-briefs"])
    for row in reviews:
        record = rr.mutate(BASES["record"], row["record"]["mutate"])
        identity = rr.mutate(BASES["identity"], row["identity"]["mutate"])
        identity["record"] = {"path": row["recordPath"], "sha256": rr.file_sha256(rr.serialize(record))}
        assert not (record_v.is_valid(record) and identity_v.is_valid(identity)), row["id"]
        assert row["expect"] == "SHAPE"
    for row in registries:
        assert not briefs_v.is_valid(rr.mutate(BASES["registry"], row["mutate"])), row["id"]
        assert row["expect"] == "SHAPE"


def test_the_published_registry_pins_each_current_brief_by_its_file_bytes():
    # RR2C1 NOTE 12: the latest version of each chain matches the file at its path; a superseded version keeps its own.
    registry = rr.load_registry((HERE / "briefs.json").read_bytes())
    latest = [b for b in registry["briefs"] if "supersededAt" not in b]
    assert latest
    for b in latest:
        assert rr.file_sha256((ROOT / b["path"]).read_bytes()) == b["sha256"], b["path"]


def test_the_review_codes_are_in_b6s_order():
    assert rr.REVIEW_CODES == ("NO_IDENTITY", "NO_BRIEF_DIGEST", "SHAPE", "UNKNOWN_KIND", "BINDING", "PLACEHOLDER_ID",
                               "NOT_INDEPENDENT", "IDENTITY_MISMATCH", "SUBJECT_FORM", "SUBJECT_REPOSITORY",
                               "BRIEF_NOT_FOR_SERIES", "BRIEF_SUPERSEDED", "VERDICT", "RULING", "SUBJECT_MISMATCH",
                               "PRIVACY")
    assert rr.SERIES_CODES == ("DUPLICATE_ROUND", "SERIES_GAP", "SERIES_FORK", "DUPLICATE_IDENTITY")
    reached = {row["expect"] for row in VECTORS["reviews"]} - {None}
    assert reached == set(rr.REVIEW_CODES)
    series_codes = {row["expect"] for row in VECTORS["series"]} - {None}
    # Every series code is reached; a series row may also stop at a round's own code (one identity for two records).
    assert set(rr.SERIES_CODES) <= series_codes <= set(rr.SERIES_CODES) | set(rr.REVIEW_CODES)


@pytest.mark.parametrize("name,schema,required,optional", [
    ("review-record", rr.RECORD_SCHEMA, rr.RECORD_REQUIRED, rr.RECORD_OPTIONAL),
    ("review-identity", rr.IDENTITY_SCHEMA, rr.IDENTITY_REQUIRED, rr.IDENTITY_OPTIONAL),
    ("oracle-identity", rr.ORACLE_SCHEMA, rr.ORACLE_REQUIRED, rr.ORACLE_OPTIONAL),
])
def test_each_schema_states_the_models_closed_members(name, schema, required, optional):
    doc = SCHEMAS[name]
    assert doc["$id"] == schema and doc["additionalProperties"] is False
    assert doc["properties"]["schemaVersion"] == {"const": schema}
    assert sorted(doc["required"]) == sorted(required)
    assert set(doc["properties"]) == set(required) | set(optional)


def test_kind_and_agent_ids_are_plain_strings_and_the_operator_is_the_lane_session():
    plain = {"type": "string", "maxLength": 4000}
    record, identity, oracle = SCHEMAS["review-record"], SCHEMAS["review-identity"], SCHEMAS["oracle-identity"]
    assert record["properties"]["kind"] == plain
    assert identity["properties"]["reviewer"]["properties"]["agentId"] == plain
    assert identity["properties"]["author"]["properties"]["agentIds"]["items"] == plain
    assert oracle["properties"]["oracle"]["properties"]["agentId"] == plain
    for doc in (identity, oracle):
        operator = doc["properties"]["operator"]
        assert operator["properties"]["role"] == {"const": "LANE_SESSION"}
        assert operator["properties"]["agentId"] == plain


def test_the_registry_schema_lists_the_four_kinds():
    briefs = SCHEMAS["review-briefs"]
    assert sorted(briefs["properties"]["kinds"]["required"]) == sorted(rr.KINDS)
    assert briefs["properties"]["briefs"]["items"]["properties"]["kind"] == {"enum": list(rr.KINDS)}


def test_the_published_registry_and_frozen_list_load():
    registry = rr.load_registry((HERE / "briefs.json").read_bytes())
    assert set(registry["kinds"]) == set(rr.KINDS)
    legacy = rr.load_legacy((HERE / "legacy-review-records.json").read_bytes())
    assert all(e["path"].endswith(".json") for e in legacy["entries"])
    assert all(rr._is_oracle_test(e["path"]) for e in legacy["oracleTests"])


def test_the_oracle_class_is_the_evolution_surface_records():
    record = es.load((ROOT / "architecture/evolution-surface/evolution-surface.json").read_bytes())
    cls = next(c for c in record["levels"]["programme"]["classes"] if c["id"] == "ORACLE_TESTS")
    assert cls["paths"] == [{"under": rr.ORACLE_TESTS[0], "name": rr.ORACLE_TESTS[1]}]


def test_a_check_takes_bytes_and_a_path_never_a_parsed_object():
    record = rr.serialize(BASES["record"])
    identity = json.loads(json.dumps(BASES["identity"]))
    identity["record"] = {"path": "architecture/x/review-round1.json", "sha256": rr.file_sha256(record)}
    with pytest.raises(rr.Refused) as refused:
        rr.check_review(BASES["record"], "architecture/x/review-round1.json", rr.serialize(identity), None, REGISTRY)
    assert refused.value.code == "SHAPE"
    facts = rr.check_review(record, "architecture/x/review-round1.json", rr.serialize(identity), None, REGISTRY)
    assert facts == {"kind": "CONTRACT", "series": "EXAMPLE-001/contract", "round": 1, "verdict": "PASS_FOR_ADOPTION",
                     "passing": True, "headBound": False, "decision": "NONE_NEEDED", "full": True}


def test_the_binding_is_the_file_byte_sha256():
    record = rr.serialize(BASES["record"])
    reindented = json.dumps(BASES["record"], indent=2).encode("utf-8") + b"\n"
    assert rr.file_sha256(record) != rr.file_sha256(reindented)
    identity = json.loads(json.dumps(BASES["identity"]))
    identity["record"] = {"path": "architecture/x/review-round1.json", "sha256": rr.file_sha256(record)}
    with pytest.raises(rr.Refused) as refused:
        rr.check_review(reindented, "architecture/x/review-round1.json", rr.serialize(identity), None, REGISTRY)
    assert refused.value.code == "BINDING"


def test_privacy_matches_the_legacy_term_by_digest_prefix_only(monkeypatch):
    word = "zyxwvut"
    assert rr.privacy_hits("a " + word + " b")["legacyTerm"] == 0
    monkeypatch.setattr(rr, "LEGACY_TERM_PREFIX", hashlib.sha256(word.encode("ascii")).hexdigest()[:16])
    assert rr.privacy_hits("a " + word + " b")["legacyTerm"] == 1
    assert rr.privacy_hits("a " + word + "s b")["legacyTerm"] == 0  # a run of eight letters is not the term


def test_the_published_name_token_table_is_empty_and_filled_only_by_the_local_loader(tmp_path):
    # Owner Q-RR2-NAMES ("Load hashes locally"): no token digest is published; local scans load them from a file.
    assert rr.NAME_TOKEN_SHA256 == {}
    word = "qzvkwy"
    assert rr.privacy_hits("a " + word + " b")["names"] == 0
    local = tmp_path / "tokens.json"
    local.write_bytes(json.dumps({"6": [hashlib.sha256(word.encode("ascii")).hexdigest()]}).encode("ascii"))
    try:
        assert rr.load_name_tokens(local) == 1
        assert rr.privacy_hits("a " + word.upper() + " b")["names"] == 1
        for bad in (b"[]", b'{"6": []}', b'{"0": ["%s"]}' % (b"0" * 64), b'{"6": ["ABC"]}'):
            local.write_bytes(bad)
            with pytest.raises(rr.Refused):
                rr.load_name_tokens(local)
        assert rr.privacy_hits(word)["names"] == 1  # a refused file leaves the table as it was
    finally:
        rr.NAME_TOKEN_SHA256 = {}


def _string_lists(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from _string_lists(item)
    elif isinstance(value, list):
        if value and all(isinstance(item, str) for item in value):
            yield "".join(value)
        for item in value:
            yield from _string_lists(item)


def test_no_vector_parts_join_into_a_published_privacy_hit():
    # Q-RR2-NAMES: parts that a vector joins at test time hold only the shapes they are meant to show. With the real
    # token digests loaded, the lanes' local scan runs the same walk.
    joined = list(_string_lists(VECTORS))
    assert joined
    hits = [rr.privacy_hits(text) for text in joined]
    assert sum(h["names"] for h in hits) == 0 and sum(h["legacyTerm"] for h in hits) == 0
    assert sum(h["absolutePaths"] for h in hits) == 3 and sum(h["emails"] for h in hits) == 3


def test_every_published_file_of_the_contract_is_private():
    files = [HERE / name for name in ("vectors.json", "briefs.json", "README.md", "REVIEW_BRIEF.md",
                                      "legacy-review-records.json")] + [
        ROOT / "scripts/review_record.py"] + [ROOT / "schemas" / ("%s.schema.json" % n) for n in SCHEMAS]
    for path in files:
        assert rr.privacy_hits(path.read_bytes()) == {"names": 0, "legacyTerm": 0, "absolutePaths": 0, "emails": 0}, path


# ---------------------------------------------------------------- check_tree on synthetic trees

def _write(root: Path, rel: str, raw: bytes) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


def _round_files(n: int, record_mutation=(), identity_mutation=(), directory="architecture/example"):
    rec = rr.mutate(BASES["record"], [{"path": ["round"], "value": n}] + list(record_mutation))
    raw = rr.serialize(rec)
    rel = "%s/review-round%d.json" % (directory, n)
    ident = rr.mutate(BASES["identity"], list(identity_mutation))
    ident["record"] = {"path": rel, "sha256": rr.file_sha256(raw)}
    return {rel: raw, "%s/review-identity-round%d.json" % (directory, n): rr.serialize(ident)}


def _legacy(entries=(), oracles=()):
    return rr.load_legacy({"schemaVersion": rr.LEGACY_SCHEMA, "baseCommit": "0" * 40,
                           "entries": sorted(entries, key=lambda e: e["path"]),
                           "oracleTests": sorted(oracles, key=lambda e: e["path"])})


def _tree(tmp_path, files):
    for rel, raw in files.items():
        _write(tmp_path, rel, raw)
    return tmp_path


def _code(fn, *args):
    try:
        fn(*args)
        return None
    except rr.Refused as refused:
        return refused.code


def test_tree_with_one_valid_series_and_a_frozen_record_passes(tmp_path):
    files = _round_files(1, [{"path": ["verdict"], "value": "CHANGES_REQUIRED"}])
    files.update(_round_files(2, [{"path": ["subject", "commit"], "value": "c" * 40},
                                  {"path": ["subject", "tree"], "value": "d" * 40},
                                  {"path": ["base"], "value": BASES["record"]["subject"]}],
                              [{"path": ["subject", "commit"], "value": "c" * 40},
                               {"path": ["subject", "tree"], "value": "d" * 40},
                               {"path": ["base"], "value": BASES["record"]["subject"]}]))
    frozen = b'{"verdict": "PASS_FOR_SOURCE_PUBLICATION"}\n'
    files["legal/old/review-round1.json"] = frozen
    root = _tree(tmp_path, files)
    legacy = _legacy([{"path": "legal/old/review-round1.json", "sha256": rr.file_sha256(frozen)}])
    assert rr.check_tree(root, legacy, REGISTRY, "harness-onion") == {"legacyRecords": 1, "series": 1, "oracleTests": 0,
                                                                     "oracleIdentities": 0}


def test_tree_refuses_a_changed_or_unlisted_legacy_record(tmp_path):
    frozen = b'{"verdict": "CHANGES_REQUIRED"}\n'
    root = _tree(tmp_path, {"legal/old/review-round1.json": frozen + b" "})
    legacy = _legacy([{"path": "legal/old/review-round1.json", "sha256": rr.file_sha256(frozen)}])
    assert _code(rr.check_tree, root, legacy, REGISTRY, "harness-onion") == "LEGACY_CHANGED"
    other = tmp_path / "other"
    _write(other, "architecture/x/review-round-final.json", frozen)
    assert _code(rr.check_tree, other, _legacy(), REGISTRY, "harness-onion") == "LEGACY_CHANGED"


def test_tree_refuses_a_legacy_path_rewritten_into_a_valid_v2_round(tmp_path):
    files = _round_files(1)
    root = _tree(tmp_path, files)
    legacy = _legacy([{"path": "architecture/example/review-round1.json", "sha256": "0" * 64}])
    assert _code(rr.check_tree, root, legacy, REGISTRY, "harness-onion") == "LEGACY_CHANGED"


def test_tree_refuses_a_v2_round_without_its_identity(tmp_path):
    files = _round_files(1)
    del files["architecture/example/review-identity-round1.json"]
    assert _code(rr.check_tree, _tree(tmp_path, files), _legacy(), REGISTRY, "harness-onion") == "NO_IDENTITY"


def test_tree_judges_each_round_and_the_series(tmp_path):
    files = _round_files(1, [{"path": ["subject", "repository"], "value": "mas-harness-operator"}],
                         [{"path": ["subject", "repository"], "value": "mas-harness-operator"}])
    assert _code(rr.check_tree, _tree(tmp_path, files), _legacy(), REGISTRY, "harness-onion") == "SUBJECT_REPOSITORY"
    gap = tmp_path / "gap"
    _tree(gap, dict(_round_files(1), **_round_files(3)))
    assert _code(rr.check_tree, gap, _legacy(), REGISTRY, "harness-onion") == "SERIES_GAP"


def test_tree_requires_a_frozen_oracle_test_or_a_valid_oracle_identity_for_each_oracle_test(tmp_path):
    oracle_file = b"import unittest\n"
    root = _tree(tmp_path, {"tests/test_example_oracle.py": oracle_file})
    assert _code(rr.check_tree, root, _legacy(), REGISTRY, "harness-onion") == "ORACLE_MISSING"
    frozen = _legacy(oracles=[{"path": "tests/test_example_oracle.py", "sha256": rr.file_sha256(oracle_file)}])
    assert rr.check_tree(root, frozen, REGISTRY, "harness-onion")["oracleTests"] == 1
    # Q-RR2-FROZEN (rev 4's stricter rule): a frozen oracle test is frozen with its bytes, so an edit needs an identity.
    _write(root, "tests/test_example_oracle.py", oracle_file + b"# bumped\n")
    assert _code(rr.check_tree, root, frozen, REGISTRY, "harness-onion") == "ORACLE_MISSING"
    _write(root, "tests/test_example_oracle.py", oracle_file)
    identity = rr.mutate(BASES["oracle"], [{"path": ["file"], "value": {"path": "tests/test_example_oracle.py",
                                                                        "sha256": rr.file_sha256(oracle_file)}}])
    _write(root, "architecture/example/oracle-identity.json", rr.serialize(identity))
    assert rr.check_tree(root, _legacy(), REGISTRY, "harness-onion")["oracleIdentities"] == 1
    _write(root, "tests/test_example_oracle.py", oracle_file + b"# edited\n")
    assert _code(rr.check_tree, root, _legacy(), REGISTRY, "harness-onion") == "ORACLE_DIGEST"


def test_tree_refuses_a_malformed_oracle_identity(tmp_path):
    root = _tree(tmp_path, {"architecture/example/oracle-identity.json": b'{"schemaVersion": "x"}\n'})
    assert _code(rr.check_tree, root, _legacy(), REGISTRY, "harness-onion") == "SHAPE"


def test_tree_ignores_records_beneath_git_and_caches(tmp_path):
    root = _tree(tmp_path, {".git/review-round1.json": b"{}", "x/__pycache__/review-round1.json": b"{}"})
    assert rr.check_tree(root, _legacy(), REGISTRY, "harness-onion") == {"legacyRecords": 0, "series": 0,
                                                                        "oracleTests": 0, "oracleIdentities": 0}
