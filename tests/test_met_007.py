"""Exact source lineage for MET-007; DATA-CORRECTNESS-001 and R14's registration row (K = 1, publishing LAB-SYNC-001): the data-correctness record with its schema, vectors, model, checker and tests, R14's successor rows, plan page and allowed names, and the product packet; the head keeps the full fan-in (8 own and 99 predecessor routes, every catalog walk and round trip, the full payload loop), and the semantic check (V1, E1, E2, E3, E4, V4, V5, V6) has a failing case for every refusal, each on plain data."""
import ast
import json
from copy import deepcopy
import os
import re
import stat
from pathlib import Path
from types import MappingProxyType

import pytest

from scripts import validate_met_007 as profile
from scripts import validate_met_006 as m006
from scripts import validate_met_perf_049 as p049
from scripts import validate_met_adopt_008 as a008
from scripts import validate_met_registry_001 as r001
from scripts import validate_met_verify_007 as v007
from scripts import validate_met_perf_047 as p047
from scripts import validate_authority_map as a007
from scripts import validate_met_perf_046 as v046
from scripts import validate_met_verify_006 as v006
from scripts import validate_met_sector_005 as sec5
from scripts import validate_met_perf_045 as perf45
from scripts import validate_met_sector_004 as sec4
from scripts import validate_met_verify_005 as vf5
from scripts import validate_met_sector_003 as sec3
from scripts import validate_chain_product_publish as cpp
from scripts import validate_release_profile as adopt6
from scripts import validate_edge_record_v12 as ev12
from scripts import validate_met_perf_043 as perf43
from scripts import validate_met_gov_005 as gov5
from scripts import validate_met_adopt_005 as adopt5
from scripts import validate_met_gov_004 as gov4
from scripts import validate_met_linux_008 as ml8
from scripts import validate_policy_observation_digests_v2 as pod2
from scripts import validate_met_linux_009 as ml9
from scripts import validate_linux_probe_kit_admission as lpka
from scripts import validate_linux_probe_interface as lpi
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


def changed_test():
    return next(path for path in profile._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert profile.validate() is None
    current = packets()
    accepted = profile.historical_catalog(current)
    assert len(current) == 300 and len(accepted) == 298
    assert set(accepted) == set(current) - {profile.NEW_PACKET, *profile.PRODUCT_PACKETS}
    assert len(m006.historical_catalog(current)) == 297
    assert len(p049.historical_catalog(current)) == 296
    assert len(a008.historical_catalog(current)) == 295
    assert len(r001.historical_catalog(current)) == 293
    assert len(v007.historical_catalog(current)) == 289
    assert len(p047.historical_catalog(current)) == 288
    assert len(a007.historical_catalog(current)) == 287
    assert len(v046.historical_catalog(current)) == 286
    assert len(v006.historical_catalog(current)) == 283
    assert len(sec5.historical_catalog(current)) == 281
    assert len(perf45.historical_catalog(current)) == 280
    assert len(sec4.historical_catalog(current)) == 278
    assert len(vf5.historical_catalog(current)) == 275
    assert len(sec3.historical_catalog(current)) == 273
    assert len(cpp.historical_catalog(current)) == 272
    assert len(adopt6.historical_catalog(current)) == 271
    assert len(ev12.historical_catalog(current)) == 270
    assert len(perf43.historical_catalog(current)) == 269
    assert len(gov5.historical_catalog(current)) == 268
    assert len(adopt5.historical_catalog(current)) == 267
    assert len(gov4.historical_catalog(current)) == 266
    assert len(ml8.historical_catalog(current)) == 265
    assert len(pod2.historical_catalog(current)) == 264
    assert len(ml9.historical_catalog(current)) == 263
    assert len(lpka.historical_catalog(current)) == 262
    assert len(lpi.historical_catalog(current)) == 261
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
    m006_before = m006.historical_bytes(path, current)
    assert m006.current_test_bytes(m006_before) == current
    p049_before = p049.historical_bytes(path, current)
    assert p049.current_test_bytes(p049_before) == current
    a008_before = a008.historical_bytes(path, current)
    assert a008.current_test_bytes(a008_before) == current
    r001_before = r001.historical_bytes(path, current)
    assert r001.current_test_bytes(r001_before) == current
    v007_before = v007.historical_bytes(path, current)
    assert v007.current_test_bytes(v007_before) == current
    p047_before = p047.historical_bytes(path, current)
    assert p047.current_test_bytes(p047_before) == current
    a007_before = a007.historical_bytes(path, current)
    assert a007.current_test_bytes(a007_before) == current
    v046_before = v046.historical_bytes(path, current)
    assert v046.current_test_bytes(v046_before) == current
    v006_before = v006.historical_bytes(path, current)
    assert v006.current_test_bytes(v006_before) == current
    sec5_before = sec5.historical_bytes(path, current)
    assert sec5.current_test_bytes(sec5_before) == current
    perf45_before = perf45.historical_bytes(path, current)
    assert perf45.current_test_bytes(perf45_before) == current
    sec4_before = sec4.historical_bytes(path, current)
    assert sec4.current_test_bytes(sec4_before) == current
    vf5_before = vf5.historical_bytes(path, current)
    assert vf5.current_test_bytes(vf5_before) == current
    sec3_before = sec3.historical_bytes(path, current)
    assert sec3.current_test_bytes(sec3_before) == current
    cpp_before = cpp.historical_bytes(path, current)
    assert cpp.current_test_bytes(cpp_before) == current
    adopt6_before = adopt6.historical_bytes(path, current)
    assert adopt6.current_test_bytes(adopt6_before) == current
    ev12_before = ev12.historical_bytes(path, current)
    assert ev12.current_test_bytes(ev12_before) == current
    perf43_before = perf43.historical_bytes(path, current)
    assert perf43.current_test_bytes(perf43_before) == current
    gov5_before = gov5.historical_bytes(path, current)
    assert gov5.current_test_bytes(gov5_before) == current
    adopt5_before = adopt5.historical_bytes(path, current)
    assert adopt5.current_test_bytes(adopt5_before) == current
    gov4_before = gov4.historical_bytes(path, current)
    assert gov4.current_test_bytes(gov4_before) == current
    ml8_before = ml8.historical_bytes(path, current)
    assert ml8.current_test_bytes(ml8_before) == current
    pod2_before = pod2.historical_bytes(path, current)
    assert pod2.current_test_bytes(pod2_before) == current
    ml9_before = ml9.historical_bytes(path, current)
    assert ml9.current_test_bytes(ml9_before) == current
    lpka_before = lpka.historical_bytes(path, current)
    assert lpka.current_test_bytes(lpka_before) == current
    lpi_before = lpi.historical_bytes(path, current)
    assert lpi.current_test_bytes(lpi_before) == current
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


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "m006_old", "p049_old", "a008_old", "r001_old", "v007_old", "p047_old", "a007_old", "v046_old", "v006_old", "sec5_old", "perf45_old", "sec4_old", "vf5_old", "sec3_old", "cpp_old", "adopt6_old", "ev12_old", "perf43_old", "gov5_old", "adopt5_old", "gov4_old", "ml8_old", "pod2_old", "ml9_old", "lpka_old", "lpi_old", "lkg_old", "pks_old", "rrv_old", "pod_old", "evs_old", "e9_old", "ccomp_old", "i6v4_old", "dcap_old", "np5_old", "lrp_old", "wpa3_old", "cfp3_old", "sol_old", "mx6_old", "np4_old", "tcv1_old", "wpa2_old", "la2_old", "i5v4_old", "cdh_old", "cfp2_old", "smx_old", "phr_old", "sv4_old", "hs43_old", "rav3_old", "deadlines_old", "events_old", "filters_old", "loop_old", "manifest_old", "ledger_old", "adoption_old", "amendment_old", "bprofile_old", "mprofile_old", "eprofile_old", "lprofile_old", "fprofile_old", "oprofile_old", "uprofile_old", "jprofile_old", "kprofile_old", "tprofile_old", "zprofile_old", "yprofile_old", "xprofile_old", "pprofile_old", "aprofile_old", "vprofile_old", "cprofile_old", "qprofile_old", "hprofile_old", "dprofile_old", "sprofile_old", "wprofile_old", "rprofile_old", "gprofile_old", "iprofile_old", "nprofile_old", "resolution_old", "account_old", "canary_old", "isolated_old", "portable_old", "proof_old", "recheck_old", "verifier_old", "linux_old", "performance_old", "runner_old", "roadmap_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = profile.historical_bytes(path, raw) if route in ("current_test", "old_bytes") else None
    current_packets = packets() if route in ("catalog", "payloads") else None
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
    old_m006 = m006.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "m006_old" else None
    old_p049 = p049.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "p049_old" else None
    old_a008 = a008.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "a008_old" else None
    old_r001 = r001.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "r001_old" else None
    old_v007 = v007.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "v007_old" else None
    old_p047 = p047.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "p047_old" else None
    old_a007 = a007.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "a007_old" else None
    old_v046 = v046.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "v046_old" else None
    old_v006 = v006.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "v006_old" else None
    old_sec5 = sec5.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "sec5_old" else None
    old_perf45 = perf45.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "perf45_old" else None
    old_sec4 = sec4.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "sec4_old" else None
    old_vf5 = vf5.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "vf5_old" else None
    old_sec3 = sec3.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "sec3_old" else None
    old_cpp = cpp.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "cpp_old" else None
    old_adopt6 = adopt6.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "adopt6_old" else None
    old_ev12 = ev12.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "ev12_old" else None
    old_perf43 = perf43.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "perf43_old" else None
    old_gov5 = gov5.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "gov5_old" else None
    old_adopt5 = adopt5.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "adopt5_old" else None
    old_gov4 = gov4.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "gov4_old" else None
    old_ml8 = ml8.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "ml8_old" else None
    old_pod2 = pod2.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "pod2_old" else None
    old_ml9 = ml9.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "ml9_old" else None
    old_lpka = lpka.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "lpka_old" else None
    old_lpi = lpi.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "lpi_old" else None
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
        "payloads": lambda: profile.validate_packet_payloads(current_packets),
        "m006_old": lambda: m006.historical_bytes(roadmap.MASTER_PATH, old_m006),
        "p049_old": lambda: p049.historical_bytes(roadmap.MASTER_PATH, old_p049),
        "a008_old": lambda: a008.historical_bytes(roadmap.MASTER_PATH, old_a008),
        "r001_old": lambda: r001.historical_bytes(roadmap.MASTER_PATH, old_r001),
        "v007_old": lambda: v007.historical_bytes(roadmap.MASTER_PATH, old_v007),
        "p047_old": lambda: p047.historical_bytes(roadmap.MASTER_PATH, old_p047),
        "a007_old": lambda: a007.historical_bytes(roadmap.MASTER_PATH, old_a007),
        "v046_old": lambda: v046.historical_bytes(roadmap.MASTER_PATH, old_v046),
        "v006_old": lambda: v006.historical_bytes(roadmap.MASTER_PATH, old_v006),
        "sec5_old": lambda: sec5.historical_bytes(roadmap.MASTER_PATH, old_sec5),
        "perf45_old": lambda: perf45.historical_bytes(roadmap.MASTER_PATH, old_perf45),
        "sec4_old": lambda: sec4.historical_bytes(roadmap.MASTER_PATH, old_sec4),
        "vf5_old": lambda: vf5.historical_bytes(roadmap.MASTER_PATH, old_vf5),
        "sec3_old": lambda: sec3.historical_bytes(roadmap.MASTER_PATH, old_sec3),
        "cpp_old": lambda: cpp.historical_bytes(roadmap.MASTER_PATH, old_cpp),
        "adopt6_old": lambda: adopt6.historical_bytes(roadmap.MASTER_PATH, old_adopt6),
        "ev12_old": lambda: ev12.historical_bytes(roadmap.MASTER_PATH, old_ev12),
        "perf43_old": lambda: perf43.historical_bytes(roadmap.MASTER_PATH, old_perf43),
        "gov5_old": lambda: gov5.historical_bytes(roadmap.MASTER_PATH, old_gov5),
        "adopt5_old": lambda: adopt5.historical_bytes(roadmap.MASTER_PATH, old_adopt5),
        "gov4_old": lambda: gov4.historical_bytes(roadmap.MASTER_PATH, old_gov4),
        "ml8_old": lambda: ml8.historical_bytes(roadmap.MASTER_PATH, old_ml8),
        "pod2_old": lambda: pod2.historical_bytes(roadmap.MASTER_PATH, old_pod2),
        "ml9_old": lambda: ml9.historical_bytes(roadmap.MASTER_PATH, old_ml9),
        "lpka_old": lambda: lpka.historical_bytes(roadmap.MASTER_PATH, old_lpka),
        "lpi_old": lambda: lpi.historical_bytes(roadmap.MASTER_PATH, old_lpi),
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
    with pytest.raises(ValueError, match="data correctness history authority digest"):
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
    assert len(profile.historical_catalog(current)) == 298


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
    assert len(profile.historical_catalog(current)) == 298
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
    assert len(rules) == 300 and len(parsed) == 299
    assert profile._packet_rules() is rules and len(parsed) == 299
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
    with pytest.raises(ValueError, match="data correctness history authority digest"):
        profile.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = packets()
    profile.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "data-correctness-authority.json").write_bytes(
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
    with pytest.raises(ValueError, match="data correctness validator drift"):
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
    for module in (profile, m006, p049, a008, r001, v007, p047, a007, v046, v006, sec5, perf45, sec4, vf5, sec3, cpp, adopt6, ev12, perf43, gov5, adopt5, gov4, ml8, pod2, ml9, lpka, lpi, lkg, pks, rrv, pod, evs, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner):
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
    expected = {module.__name__: 1 for module in (profile, m006, p049, a008, r001, v007, p047, a007, v046, v006, sec5, perf45, sec4, vf5, sec3, cpp, adopt6, ev12, perf43, gov5, adopt5, gov4, ml8, pod2, ml9, lpka, lpi, lkg, pks, rrv, pod, evs, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner)}
    if route == "current_test":
        # The forward route reads this layer's newest bytes and then projects them forward once more.
        assert all(counts[name] >= 1 for name in expected) and set(counts) == set(expected)
    else:
        assert counts == expected


# MET-007 (DATA-CORRECTNESS-001 with R14's registration row, K = 1, publishing LAB-SYNC-001): this era's check, and a
# failing case for every check. Every mutant below is applied to plain data handed to the layer's pure checks: nothing in
# the layer, the model, the checker or the library is patched or swapped.
import base64 as _b64

VALIDATE = profile.validate_met_007
OWN_PATH = "task-packets/MET-007.yaml"
PRODUCT = "LAB-SYNC-001"
V_TESTS = {
    "V1": ("test_v1_every_era_file_is_bound_by_its_digest", "test_v1_the_packet_files_are_exactly_the_twenty_one"),
    "E1": ("test_e1_the_model_replays_every_vector_and_the_record_passes_its_checker",),
    "E2": ("test_e2_the_base_files_are_unchanged",),
    "E3": ("test_e3_authored_hunks_only_at_the_named_lines",),
    "E4": ("test_e4_the_effective_catalog_equals_the_raw_catalog",),
    "V4": ("test_v4_the_registry_differs_from_the_base_by_the_one_rider",),
    "V5": ("test_v5_the_product_with_its_comparator_and_r8_clause_2",),
    "V6": ("test_v6_the_hunk_class_record_rechecks_in_full",),
}
V1_BOUND = "MET-007 reviewed bytes are bound: "
V1_DRIFT = "unreviewed MET-007 source: "
V1_FILES = "MET-007 V1 the packet files are exactly the twenty-one"
V1_FILE = "MET-007 V1 a packet file's bytes equal its pinned digest: "
E1_VECTORS = "MET-007 E1 every vector replays to its expectation through the era model"
E1_RECORD = "MET-007 E1 the record passes its checker (DC_SHAPE to DC_VECTORS)"
E2_BYTES = "MET-007 E2 the seven base files equal their base bytes"
E2_NAMED = "MET-007 E2 this step changes none of the seven base files"
E3_ONLY = "MET-007 E3 class-other hunks fall only on the named files"
E3_CARRY = "MET-007 E3 the named file carries its authored hunk: "
E3_LINES = "MET-007 E3 an authored hunk lies at its named lines: "
E4 = "MET-007 E4 the effective catalog equals the raw catalog (28 services, 129 dependency entries, in order)"
V4_MESSAGE = "the registry differs from the base by exactly the MET-007 packet rider"
V5_SET = "MET-007 V5 product set"
V5_BYTES = "MET-007 V5 product bytes: "
V5_FACTS = "MET-007 V5 product facts: "
V5_PINS = "MET-007 V5 product pins: "
V5_COMPARATOR = "MET-007 V5 product comparator: "
V5_INHERIT = "MET-007 V5 the product keeps its comparator's commands byte-exact and in order (R13): "
V5_R8 = "MET-007 V5 R8 clause 2 admits the product's repository at slot 288: "
V6_CLOSED = "MET-007 V6 the hunk-class record is closed and names this layer's authority"
V6_PINNED = "MET-007 V6 the hunk-class record's vocabulary and rule digest are v2.5's"
V6_CONTEXT = "MET-007 V6 the hunk-class record's context is this step's names"
V6_COVER = "MET-007 V6 the hunk-class record lists one class per hunk for exactly the changed files"
V6_RECHECK = "MET-007 V6 a recorded class re-checks by position: "
READER = "ci/chain_checkpoint.py"
NAMED = "tests/test_task_packets.py"
CATALOG = "architecture/services.yaml"
REGISTRY_YAML = "architecture/repositories.yaml"


def _chain_packets():
    """The live packets, read as validate() reads them (each file's bytes through the layer, parsed by safe_load)."""
    return {path.stem: profile.safe_load(profile.regular_bytes("task-packets/" + path.name))
            for path in sorted((profile.ROOT / "task-packets").glob("*.yaml"))}


def _sha(raw):
    import hashlib
    return hashlib.sha256(raw).hexdigest()


def _raises(message, call):
    with pytest.raises(ValueError, match=re.escape(message)):
        call()


def test_every_check_has_a_test_that_makes_it_fail():
    names = {name for name, value in globals().items() if name.startswith("test_") and callable(value)}
    assert sorted(V_TESTS) == ["E1", "E2", "E3", "E4", "V1", "V4", "V5", "V6"]
    assert all(test in names for tests in V_TESTS.values() for test in tests)


def test_the_contract_holds_for_this_era():
    assert VALIDATE(_chain_packets()) is None


def test_the_era_holds_the_packet_files_the_base_files_and_the_checker_reads():
    assert profile.PRODUCT_PACKETS == (PRODUCT,)
    assert len(profile.PACKET_FILES) == 21 and len(profile.BASE_FILES) == 7 and len(profile.ERA_SHA256) == 41
    assert profile.PACKET_FILES[-1] == READER      # [R4-OQ1]: the head pins the v2.5 reader among its packet files
    assert len(profile.VECTORS) == 13 and set(profile.VECTORS) == set(profile.VECTOR_EXPECT) <= set(profile.PACKET_FILES)
    assert set(profile.PACKET_FILES) | set(profile.BASE_FILES) | {profile.REGISTRY_PATH, profile.PACKET_BRIEF, READER} \
        <= set(profile.ERA_SHA256)
    for path, expected in profile.ERA_SHA256.items():
        assert _sha(profile.reviewed_bytes(path)) == expected
    assert dict(profile.BASE_SHA256) == {path: profile.ERA_SHA256[path] for path in profile.BASE_FILES}
    record = profile.authority()
    assert sorted(record) == ["acceptedBase", "authorityPacket", "baselinePackets", "changedFiles", "newFiles",
                              "packetSha256", "productComparators", "productPackets", "schemaVersion",
                              "validatorNormalizedSha256"]
    assert len(record["baselinePackets"]) == 298 and list(record["productPackets"]) == [PRODUCT]
    assert record["productComparators"] == {PRODUCT: {"packet": "LAB-REPO-001", "sha256": profile.COMPARATOR_SHA256}}
    assert record["baselinePackets"]["LAB-REPO-001"] == profile.COMPARATOR_SHA256
    assert profile.HUNK_RECORD_PATH in record["newFiles"] and profile.HUNK_RECORD_PATH not in profile.ERA_SHA256
    assert set(profile.PACKET_FILES) - {READER} <= set(record["newFiles"])     # the v2.5 reader is a changed file
    assert READER in record["changedFiles"] and READER not in record["newFiles"]
    assert profile.VALIDATOR_PATH not in record["newFiles"] and OWN_PATH not in record["newFiles"]
    assert "task-packets/%s.yaml" % PRODUCT not in record["newFiles"]
    assert set(profile.ERRATA_LINES) <= set(record["changedFiles"])


@pytest.mark.parametrize("change", ["outside_path", "outside_read", "not_a_string", "byte_appended", "crlf", "not_bytes"])
def test_v1_every_era_file_is_bound_by_its_digest(change):
    for path in profile.ERA_SHA256:
        raw = profile._verified(path)
        assert profile._era_bytes(path, raw) is raw
    raw = profile._verified(READER)
    outside = "ci/verify-offline.sh"
    mutants = {
        "outside_path": (lambda: profile._era_bytes(outside, raw), V1_BOUND + outside),
        "outside_read": (lambda: profile._verified(outside), V1_BOUND + outside),
        "not_a_string": (lambda: profile._era_bytes(Path(READER), raw), V1_BOUND),
        "byte_appended": (lambda: profile._era_bytes(READER, raw + b"\n"), V1_DRIFT + READER),
        "crlf": (lambda: profile._era_bytes(READER, raw.replace(b"\n", b"\r\n", 1)), V1_DRIFT + READER),
        "not_bytes": (lambda: profile._era_bytes(READER, raw.decode("utf-8")), V1_DRIFT + READER),
    }
    call, message = mutants[change]
    _raises(message, call)


@pytest.mark.parametrize("change", ["missing", "extra", "byte"])
def test_v1_the_packet_files_are_exactly_the_twenty_one(change):
    files = {path: profile._verified(path) for path in profile.PACKET_FILES}
    assert profile.check_packet_files(files) is None
    path = profile.PACKET_FILES[0]
    if change == "missing":
        files.pop(path)
        message = V1_FILES
    elif change == "extra":
        files[profile.PACKET_BRIEF] = profile._verified(profile.PACKET_BRIEF)
        message = V1_FILES
    else:
        files[path] = files[path] + b"\n"
        message = V1_FILE + path
    _raises(message, lambda: profile.check_packet_files(files))


@pytest.mark.parametrize("change", ["one_refusal", "not_a_list", "a_mutated_record", "a_vector_accepts", "a_vector_missing"])
def test_e1_the_model_replays_every_vector_and_the_record_passes_its_checker(change):
    current = _chain_packets()
    assert profile.validate_correctness(current) is None
    model, checker = profile._era_checker()
    replays = {path: profile._replayed(model, profile._verified(path)) for path in profile.VECTORS}
    refusals = checker.check(profile._era_read, frozenset(current))
    assert refusals == [] and profile.check_correctness(replays, refusals) is None
    message = E1_RECORD
    if change == "one_refusal":
        refusals = [("DC_COUNTS", "counts differ")]
    elif change == "not_a_list":
        refusals = None
    elif change == "a_mutated_record":
        record = json.loads(profile._verified(profile.RECORD_PATH))
        record["counts"]["deployables"] = record["counts"]["deployables"] - 1
        mutant = (json.dumps(record, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
        read = lambda path: mutant if path == profile.RECORD_PATH else profile._era_read(path)
        refusals = checker.check(read, frozenset(current))
        assert [code for code, _ in refusals] == ["DC_COUNTS"]
    elif change == "a_vector_accepts":
        path = next(p for p in profile.VECTORS if profile.VECTOR_EXPECT[p] != "ACCEPT")
        replays = dict(replays, **{path: "ACCEPT"})
        message = E1_VECTORS
    else:
        replays = {path: value for path, value in replays.items() if path != profile.VECTORS[0]}
        message = E1_VECTORS
    _raises(message, lambda: profile.check_correctness(replays, refusals))


@pytest.mark.parametrize("change", ["byte", "missing", "changed_names_one", "new_names_one", "registry_byte"])
def test_e2_the_base_files_are_unchanged(change):
    record = profile.authority()
    files = {path: profile._verified(path) for path in profile.BASE_FILES}
    changed, new = dict(record["changedFiles"]), dict(record["newFiles"])
    assert profile.check_base_files(files, changed, new) is None
    message = E2_BYTES
    if change == "byte":
        files[CATALOG] = files[CATALOG] + b"\n"
    elif change == "missing":
        files.pop(CATALOG)
    elif change == "changed_names_one":
        changed[REGISTRY_YAML], message = {"afterSha256": "0" * 64}, E2_NAMED
    elif change == "new_names_one":
        new["schemas/repositories.schema.json"], message = "0" * 64, E2_NAMED
    else:
        files[REGISTRY_YAML] = files[REGISTRY_YAML].replace(b"\n", b"\n\n", 1)
    _raises(message, lambda: profile.check_base_files(files, changed, new))


def _errata_inputs():
    record = profile.authority()
    side = json.loads(profile.reviewed_bytes(profile.HUNK_RECORD_PATH))
    befores = {path: profile._undo_this_layer(path, profile.reviewed_bytes(path)) for path in profile.ERRATA_LINES}
    return side["classes"], record["changedFiles"], befores


@pytest.mark.parametrize("change", ["other_elsewhere", "no_authored_hunk", "moved_lines"])
def test_e3_authored_hunks_only_at_the_named_lines(change):
    classes, changed, befores = _errata_inputs()
    assert profile.check_errata(classes, changed, befores) is None
    classes = json.loads(json.dumps(classes))
    position = classes[NAMED].index("other")
    if change == "other_elsewhere":
        path = next(p for p in sorted(classes) if p not in profile.ERRATA_LINES and classes[p])
        classes[path][0] = "other"
        message = E3_ONLY
    elif change == "no_authored_hunk":
        classes[NAMED] = ["cascade" if cls == "other" else cls for cls in classes[NAMED]]
        message = E3_CARRY + NAMED
    else:
        befores = dict(befores, **{NAMED: b"\n" * 10 + befores[NAMED]})
        message = E3_LINES + "%s hunk %d" % (NAMED, position)
    _raises(message, lambda: profile.check_errata(classes, changed, befores))


@pytest.mark.parametrize("change", ["parity", "count", "service_dropped", "dc_basis", "not_a_list"])
def test_e4_the_effective_catalog_equals_the_raw_catalog(change):
    current = _chain_packets()
    assert profile.validate_parity(current) is None
    raw_catalog = profile.safe_load(profile._verified(CATALOG))
    basis = json.loads(profile._verified(profile.RECORD_PATH))["basis"]["catalog"]
    _model, checker = profile._era_checker()
    refusals = checker.check(profile._era_read, frozenset(current))
    assert profile.check_parity(raw_catalog, basis, refusals) is None
    if change == "parity":
        basis = dict(basis, parity="RAW_DIFFERS")
    elif change == "count":
        basis = dict(basis, dependencyEntries=128)
    elif change == "service_dropped":
        raw_catalog = dict(raw_catalog, services=raw_catalog["services"][1:])
    elif change == "dc_basis":
        refusals = [("DC_BASIS", "raw and effective catalogs differ in names or entries")]
    else:
        refusals = None
    _raises(E4, lambda: profile.check_parity(raw_catalog, basis, refusals))


@pytest.mark.parametrize("change", ["no_rider", "second_rider", "rider_not_last", "brief_byte", "other_entry", "series"])
def test_v4_the_registry_differs_from_the_base_by_the_one_rider(change):
    raw = profile._verified(profile.REGISTRY_PATH)
    briefs = {profile.PACKET_BRIEF: profile._verified(profile.PACKET_BRIEF)}
    assert profile.check_registry(raw, briefs) is None
    registry = json.loads(raw)
    rider = registry["briefs"][-1]
    if change == "no_rider":
        registry["briefs"] = registry["briefs"][:-1]
    elif change == "second_rider":
        registry["briefs"].append(dict(rider))
    elif change == "rider_not_last":
        registry["briefs"] = [rider] + registry["briefs"][:-1]
    elif change == "brief_byte":
        briefs = {profile.PACKET_BRIEF: briefs[profile.PACKET_BRIEF] + b" "}
    elif change == "other_entry":
        registry["briefs"][0]["version"] = registry["briefs"][0]["version"] + 1
    else:
        rider["series"] = "MET-007/contract"
    mutant = (json.dumps(registry, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
    _raises(V4_MESSAGE, lambda: profile.check_registry(mutant, briefs))


def _product_inputs():
    record = profile.authority()
    raws = {name: profile.reviewed_bytes("task-packets/%s.yaml" % name) for name in profile.PRODUCT_PACKETS}
    comparators = {name: profile.reviewed_bytes("task-packets/%s.yaml" % pin["packet"])
                   for name, pin in record["productComparators"].items()}
    return raws, comparators, record, profile._allowed_names()


def _rewritten(raw, key, value):
    """The product YAML with one top-level flow line re-dumped (compact JSON, the packet's own form)."""
    lines = raw.decode("utf-8").split("\n")
    at = [i for i, line in enumerate(lines) if line.startswith(key + ": ")]
    assert len(at) == 1
    lines[at[0]] = key + ": " + json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return "\n".join(lines).encode("utf-8")


@pytest.mark.parametrize("change", ["set", "bytes", "repository", "predecessor", "allowed_path", "head_pin",
                                    "comparator_pin", "comparator_bytes", "dropped_command", "reordered_commands",
                                    "repository_not_allowed", "allowed_unreadable"])
def test_v5_the_product_with_its_comparator_and_r8_clause_2(change):
    raws, comparators, record, allowed = _product_inputs()
    assert profile.validate_products() is None
    assert type(allowed) is list and "mas-harness-research-lab" in allowed and "mas-harness-reference-lab" in allowed
    assert profile.check_products(raws, comparators, record, allowed) is None
    raw = raws[PRODUCT]
    doc = profile.safe_load(raw)
    mutant, message = None, None
    if change == "set":
        record, message = dict(record, productComparators={}), V5_SET
    elif change == "bytes":
        raws, message = {PRODUCT: raw + b"\n"}, V5_BYTES + PRODUCT
    elif change == "repository":
        mutant, message = raw.replace(b"\nrepository: mas-harness-research-lab\n", b"\nrepository: mas-harness-operator\n"), V5_FACTS + PRODUCT
    elif change == "predecessor":
        mutant, message = _rewritten(raw, "predecessors", []), V5_FACTS + PRODUCT
    elif change == "allowed_path":
        mutant, message = _rewritten(raw, "allowedPaths", ["research/", "ci/"]), V5_FACTS + PRODUCT
    elif change == "head_pin":
        head = profile.PRODUCT_FACTS[PRODUCT]["head"].encode()
        mutant, message = raw.replace(head, b"0" * len(head)), V5_PINS + PRODUCT
    elif change == "comparator_pin":
        record = dict(record, productComparators={PRODUCT: {"packet": "LAB-REPO-001", "sha256": "0" * 64}})
        message = V5_COMPARATOR + PRODUCT
    elif change == "comparator_bytes":
        comparators, message = {PRODUCT: comparators[PRODUCT] + b"\n"}, V5_COMPARATOR + PRODUCT
    elif change == "dropped_command":
        mutant = _rewritten(raw, "offlineAcceptanceCommands", doc["offlineAcceptanceCommands"][1:])
        message = V5_INHERIT + PRODUCT
    elif change == "reordered_commands":
        commands = doc["offlineAcceptanceCommands"]
        mutant = _rewritten(raw, "offlineAcceptanceCommands", [commands[1], commands[0]] + commands[2:])
        message = V5_INHERIT + PRODUCT
    elif change == "repository_not_allowed":
        allowed, message = [name for name in allowed if name != "mas-harness-research-lab"], V5_R8 + PRODUCT
    else:
        allowed, message = None, V5_R8 + PRODUCT
    if mutant is not None:
        assert mutant != raw
        raws = {PRODUCT: mutant}
        record = dict(record, productPackets={PRODUCT: _sha(mutant)})
    _raises(message, lambda: profile.check_products(raws, comparators, record, allowed))


def _hunk_inputs():
    record = profile.authority()
    raw = profile.reviewed_bytes(profile.HUNK_RECORD_PATH)
    afters = {path: profile.reviewed_bytes(path) for path, entry in record["changedFiles"].items() if "reverseHunks" in entry}
    rule = profile._era_rule(profile.READER_PATH, profile.READER_NAME)
    reader = profile._era_model(profile.READER_PATH, profile.READER_NAME)
    assert reader.RULE_V25_SHA256 == profile.HUNK_RULE_SHA256 and rule.classify is rule.classify_v25   # [R4-OQ1]
    context = profile._v24_context(record, json.loads(raw)["hunkClassContext"])
    assert context == reader.context_v24(record, json.loads(raw)["hunkClassContext"])
    assert context["products"] == [PRODUCT] and context["steps"] == [1, 2] and context["pairs"] == [[298, 300], [315, 317]]
    return raw, record["changedFiles"], afters, rule.classify, context


def test_v6_the_hunk_class_record_holds_for_this_era():
    raw, changed, afters, classify, context = _hunk_inputs()
    assert _sha(raw) == profile.authority()["newFiles"][profile.HUNK_RECORD_PATH]
    assert profile.check_hunk_record(raw, changed, afters, classify, context, profile.HUNK_RULE_SHA256) is None
    assert "other" in set(json.loads(raw)["classes"][NAMED])


@pytest.mark.parametrize("change", ["member", "authority_path", "statement", "vocabulary", "rule_sha", "reader_rule",
                                    "count_pairs", "steps", "file_missing", "count_short", "relabelled"])
def test_v6_the_hunk_class_record_rechecks_in_full(change):
    raw, changed, afters, classify, context = _hunk_inputs()
    record = json.loads(raw)
    rule_sha, message = profile.HUNK_RULE_SHA256, V6_CLOSED
    path = NAMED
    if change == "member":
        record["extra"] = 1
    elif change == "authority_path":
        record["authorityPath"] = "architecture/other-authority.json"
    elif change == "statement":
        record["outcomeStatements"] = [{"layerSlot": 287, "path": NAMED, "nodeSha256s": ["0" * 64]}]
    elif change == "vocabulary":
        record["hunkClassVocabulary"], message = record["hunkClassVocabulary"][:-1], V6_PINNED
    elif change == "rule_sha":
        record["hunkClassRuleSha256"], message = "0" * 64, V6_PINNED
    elif change == "reader_rule":
        rule_sha, message = None, V6_PINNED
    elif change == "count_pairs":
        record["hunkClassContext"]["countPairs"], message = [[313, 315]], V6_CONTEXT
    elif change == "steps":
        record["hunkClassContext"]["steps"], message = [1, 1], V6_CONTEXT
    elif change == "file_missing":
        record["classes"].pop(path)
        message = V6_COVER
    elif change == "count_short":
        record["classes"][path] = record["classes"][path][:-1]
        message = V6_COVER
    else:
        position = record["classes"][path].index("other")
        record["classes"][path][position] = "cascade"
        message = V6_RECHECK + "%s hunk %d" % (path, position)
    mutant = (json.dumps(record, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
    _raises(message, lambda: profile.check_hunk_record(mutant, changed, afters, classify, context, rule_sha))
