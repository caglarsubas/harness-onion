"""Exact source lineage for MET-REGISTRY-001; R13 mas-harness-research-lab's registration (the seventh publishing step, K = 1, publishing LAB-REPO-001): the head keeps the full fan-in (8 own and 95 predecessor routes, every catalog walk and round trip, the full payload loop), and the semantic check (V1, V2, V4, V6, R1-R7, S) has a failing case for every refusal, each on plain data."""
import ast
import json
from copy import deepcopy
import os
import re
import stat
from pathlib import Path
from types import MappingProxyType

import pytest

from scripts import validate_met_registry_001 as profile
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


def layer_packets():
    # The newer MET-ADOPT-008 layer is projected away before this layer's payload checks.
    return profile.successor.historical_catalog(packets())


def changed_test():
    return next(path for path in profile._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert profile.validate() is None
    current = packets()
    accepted = profile.historical_catalog(current)
    assert len(current) == 296 and len(accepted) == 293
    assert set(accepted) == set(current) - {profile.NEW_PACKET, *profile.PRODUCT_PACKETS, profile.successor.NEW_PACKET}
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
    assert set(table) == set(profile.authority()["baselinePackets"]) | {profile.NEW_PACKET, *profile.PRODUCT_PACKETS}
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


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "v007_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = profile.historical_bytes(path, raw) if route in ("current_test", "old_bytes") else None
    current_packets = packets() if route == "catalog" else None
    layer = layer_packets() if route == "payloads" else None
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
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
        "payloads": lambda: profile.validate_packet_payloads(layer),
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
    with pytest.raises(ValueError, match="repository registration history authority digest"):
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
    assert len(profile.historical_catalog(current)) == 293


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
    assert len(profile.historical_catalog(current)) == 293
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
    assert len(rules) == 295 and len(parsed) == 294
    assert profile._packet_rules() is rules and len(parsed) == 294
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
    with pytest.raises(ValueError, match="repository registration history authority digest"):
        profile.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = layer_packets()
    profile.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "repository-registration-authority.json").write_bytes(
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
    # The newer MET-ADOPT-008 layer refuses a mutated validator before this layer.
    with pytest.raises(ValueError, match="unreviewed current source: scripts/validate_met_registry_001.py"):
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
            assert all("validate_" not in alias.name or alias.name == "validate_met_adopt_008"
                       for alias in node.names)


def _count_authority_reads(monkeypatch):
    counts = {}
    for module in (profile.successor, profile, v007, p047, a007, v046, v006, sec5, perf45, sec4, vf5, sec3, cpp, adopt6, ev12, perf43, gov5, adopt5, gov4, ml8, pod2, ml9, lpka, lpi, lkg, pks, rrv, pod, evs, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner):
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
    expected = {module.__name__: 1 for module in (profile.successor, profile, v007, p047, a007, v046, v006, sec5, perf45, sec4, vf5, sec3, cpp, adopt6, ev12, perf43, gov5, adopt5, gov4, ml8, pod2, ml9, lpka, lpi, lkg, pks, rrv, pod, evs, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner)}
    if route == "current_test":
        # The forward route reads this layer's newest bytes and then projects them forward once more.
        assert all(counts[name] >= 1 for name in expected) and set(counts) == set(expected)
    else:
        assert counts == expected


# MET-REGISTRY-001 (R13 mas-harness-research-lab's registration): this era's check, and a failing case for every check
# (K = 1). Every mutant below is applied to plain data handed to the layer's pure checks: nothing in the layer, the
# reader or the library is patched or swapped. The layer binds R13's first product packet in the generic first-packet
# form (V2) and the registration (R1-R7 and D1, rev 5); R8 clause 2's successor function is exercised on its own vectors (S).
VALIDATE = profile.validate_met_registry_001
OWN_PATH = "task-packets/MET-REGISTRY-001.yaml"
# Each of V1, V2, V4, V6, R and S and the tests that make it fail.
V_TESTS = {
    "V1": ("test_v1_every_era_file_is_bound_by_its_digest",
           "test_v1_the_successor_record_its_schema_and_its_module_are_bound_at_root"),
    "V2": ("test_v2_the_product_rechecks_in_full",),
    "V4": ("test_v4_the_registry_differs_from_the_base_by_the_one_rider",),
    "V6": ("test_v6_the_hunk_class_record_rechecks_in_full",),
    "R": ("test_r_the_registration_rechecks_in_full",),
    "S": ("test_s_the_successor_rule_refuses",
          "test_s_placement_rows_refuse_an_unreadable_record_with_the_placement_clause"),
}
V1_BOUND = "MET-REGISTRY-001 reviewed bytes are bound: "
V1_DRIFT = "unreviewed MET-REGISTRY-001 source: "
V4_MESSAGE = "the registry differs from the base by exactly the MET-REGISTRY-001 packet rider"
V6_CLOSED = "the hunk-class record is closed and names this layer's authority"
V6_PINNED = "the hunk-class record's vocabulary and rule digest are the pinned ones"
V6_CONTEXT = "the hunk-class record's context is this step's names"
V6_COVER = "the hunk-class record lists one class per hunk for exactly the changed files"
V6_RECHECK = "a recorded class re-checks by position: "
LOCK = "scripts/check_release_lock.py"


def _chain_packets():
    """The live packets, read as validate() reads them (each file's bytes through the layer, parsed by safe_load)."""
    return {path.stem: profile.safe_load(profile.regular_bytes("task-packets/" + path.name))
            for path in sorted((profile.ROOT / "task-packets").glob("*.yaml"))}


def _sha(raw):
    import hashlib
    return hashlib.sha256(raw).hexdigest()


def test_the_contract_holds_for_this_era():
    assert VALIDATE(_chain_packets()) is None


def test_the_era_holds_the_registration_files_the_registry_the_brief_the_reader_and_v2():
    assert profile.PRODUCT_PACKETS == ("LAB-REPO-001",)
    assert len(profile.PACKET_FILES) == 14 and len(profile.FROZEN_SHA256) == 8 and len(profile.ERA_SHA256) == 27
    assert set(profile.PACKET_FILES) | set(profile.FROZEN_SHA256) | {profile.REGISTRY_PATH, profile.PACKET_BRIEF,
                                                                 profile.READER_PATH, profile.V2_MODULE,
                                                                 profile.V2_RULE} == set(profile.ERA_SHA256)
    for path, expected in profile.ERA_SHA256.items():
        assert _sha(profile.reviewed_bytes(path)) == expected
    assert not any(path.startswith("scripts/validate_") and path not in profile.PACKET_FILES for path in profile.ERA_SHA256)
    record = profile.authority()
    assert list(record["productPackets"]) == list(profile.PRODUCT_PACKETS) and record["productComparators"] == {}
    assert len(record["baselinePackets"]) == 293
    assert profile.HUNK_RECORD_PATH in record["newFiles"] and profile.HUNK_RECORD_PATH not in profile.ERA_SHA256
    assert set(profile.PACKET_FILES) <= set(record["changedFiles"]) | set(record["newFiles"])
    assert not set(profile.FROZEN_SHA256) & (set(record["changedFiles"]) | set(record["newFiles"]))
    assert profile.READER_PATH not in record["changedFiles"]
    assert profile.V2_MODULE not in record["changedFiles"] and profile.V2_RULE not in record["changedFiles"]


def test_every_check_has_a_test_that_makes_it_fail():
    names = {name for name, value in globals().items() if name.startswith("test_") and callable(value)}
    assert sorted(V_TESTS) == ["R", "S", "V1", "V2", "V4", "V6"]
    assert all(test in names for tests in V_TESTS.values() for test in tests)


# V1, this packet's files by digest ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("change", ["outside_path", "outside_read", "not_a_string", "byte_appended", "crlf",
                                    "not_bytes"])
def test_v1_every_era_file_is_bound_by_its_digest(change):
    for path in profile.ERA_SHA256:
        raw = profile._verified(path)
        assert profile._era_bytes(path, raw) is raw
    raw = profile._verified(LOCK)
    outside = "ci/verify-offline.sh"
    mutants = {
        "outside_path": (lambda: profile._era_bytes(outside, raw), V1_BOUND + outside),
        "outside_read": (lambda: profile._verified(outside), V1_BOUND + outside),
        "not_a_string": (lambda: profile._era_bytes(Path(LOCK), raw), V1_BOUND),
        "byte_appended": (lambda: profile._era_bytes(LOCK, raw + b"\n"), V1_DRIFT + LOCK),
        "crlf": (lambda: profile._era_bytes(LOCK, raw.replace(b"\n", b"\r\n", 1)), V1_DRIFT + LOCK),
        "not_bytes": (lambda: profile._era_bytes(LOCK, raw.decode("utf-8")), V1_DRIFT + LOCK),
    }
    call, message = mutants[change]
    with pytest.raises(ValueError, match=re.escape(message)):
        call()


# V1 at ROOT (VIS-284-LPORACLE condition 2): the successor record, its schema and the composition module --------------------

@pytest.mark.parametrize("path", ["architecture/repository-registration/repositories.json",
                                  "architecture/repository-registration/repositories.schema.json",
                                  "architecture/repository-registration/language-placement.json",
                                  "architecture/repository-registration/language-placement.schema.json",
                                  "scripts/repository_registration.py"])
@pytest.mark.parametrize("change", ["deleted", "byte_flipped", "emptied"])
def test_v1_the_successor_record_its_schema_and_its_module_are_bound_at_root(path, change):
    # The pin table names all three, and the layer reads every era path through _verified (validate_registration), so a
    # record, a schema or a module deleted or tampered at ROOT refuses: a missing file is not read, other bytes are not
    # the era's. Plain data only: nothing in the layer is patched.
    assert path in profile.PACKET_FILES and path in profile.ERA_SHA256
    raw = profile._verified(path)
    assert profile._era_bytes(path, raw) is raw
    if change == "deleted":
        folder, name = path.rsplit("/", 1)
        with pytest.raises(OSError):
            profile.regular_bytes(folder + "/deleted-" + name)
        return
    at = len(raw) // 2
    mutant = raw[:at] + bytes([raw[at] ^ 1]) + raw[at + 1:] if change == "byte_flipped" else b""
    with pytest.raises(ValueError, match=re.escape(V1_DRIFT + path)):
        profile._era_bytes(path, mutant)


# V4, the registry --------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("change", ["no_rider", "second_rider", "rider_not_last", "brief_byte", "other_entry",
                                    "renamed_series"])
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
        rider["series"] = "MET-REGISTRY-001/contract"
    mutant = (json.dumps(registry, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
    with pytest.raises(ValueError, match=re.escape(V4_MESSAGE)):
        profile.check_registry(mutant, briefs)


# V6, the hunk-class record -----------------------------------------------------------------------------------------------

def _hunk_inputs():
    record = profile.authority()
    raw = profile.reviewed_bytes(profile.HUNK_RECORD_PATH)
    afters = {path: profile.reviewed_bytes(path) for path in record["changedFiles"]}
    reader = profile._era_model(profile.READER_PATH, profile.READER_NAME)
    return raw, record["changedFiles"], afters, reader.classify


def test_v6_the_hunk_class_record_holds_for_this_era():
    raw, changed, afters, classify = _hunk_inputs()
    assert _sha(raw) == profile.authority()["newFiles"][profile.HUNK_RECORD_PATH]
    assert profile.check_hunk_record(raw, changed, afters, classify, profile.HUNK_RULE_SHA256) is None
    # The release lock's two conditions are a real edit: class other, never undone by the chain checkpoint.
    assert "other" in set(json.loads(raw)["classes"][LOCK])


@pytest.mark.parametrize("change", ["member", "authority_path", "vocabulary", "rule_sha", "reader_rule", "context_packet",
                                    "context_steps", "file_missing", "count_short", "not_a_string", "relabelled",
                                    "lock_relabelled", "not_json", "v22_rule"])
def test_v6_the_hunk_class_record_rechecks_in_full(change):
    raw, changed, afters, classify = _hunk_inputs()
    record = json.loads(raw)
    rule_sha, message = profile.HUNK_RULE_SHA256, V6_CLOSED
    assert profile.HUNK_VOCABULARY == ("bridge", "cascade", "other", "record", "register")
    cascade = next((path, n) for path, classes in record["classes"].items() for n, cls in enumerate(classes)
                   if cls == "cascade")
    other = record["classes"][LOCK].index("other")
    if change == "member":
        record["extra"] = 1
    elif change == "authority_path":
        record["authorityPath"] = "architecture/other-authority.json"
    elif change == "vocabulary":
        record["hunkClassVocabulary"], message = ["bridge", "cascade", "other"], V6_PINNED
    elif change == "rule_sha":
        record["hunkClassRuleSha256"], message = "0" * 64, V6_PINNED
    elif change == "v22_rule":
        record["hunkClassRuleSha256"] = "c4a77f027b244d6f1c22178fadfa7c0d4b6f7b607ada89b2eebdebc01417427b"
        record["hunkClassVocabulary"], message = ["bridge", "cascade", "other", "record"], V6_PINNED
    elif change == "reader_rule":
        rule_sha, message = None, V6_PINNED
    elif change == "context_packet":
        record["hunkClassContext"]["newPacket"], message = "MET-OTHER-001", V6_CONTEXT
    elif change == "context_steps":
        record["hunkClassContext"]["steps"], message = [1, 4], V6_CONTEXT
    elif change == "file_missing":
        record["classes"].pop(cascade[0])
        message = V6_COVER
    elif change == "count_short":
        record["classes"][cascade[0]].pop()
        message = V6_COVER
    elif change == "not_a_string":
        record["classes"][cascade[0]][cascade[1]] = ["cascade"]
        message = V6_COVER
    elif change == "relabelled":
        record["classes"][cascade[0]][cascade[1]] = "other"
        message = V6_RECHECK + "%s hunk %d" % cascade
    elif change == "lock_relabelled":
        record["classes"][LOCK][other] = "cascade"
        message = V6_RECHECK + "%s hunk %d" % (LOCK, other)
    mutant = b"{" if change == "not_json" else (json.dumps(record, indent=1, sort_keys=True) + "\n").encode("utf-8")
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.check_hunk_record(mutant, changed, afters, classify, rule_sha)


# V2, the product in the generic first-packet form ------------------------------------------------------------------------

V2_SET = "MET-REGISTRY-001 product set (a first packet has no comparator)"
V2_BYTES = "MET-REGISTRY-001 product bytes: "
V2_FACTS = "MET-REGISTRY-001 product facts: "
V2_PINS = "MET-REGISTRY-001 product pins: "
LAB = "LAB-REPO-001"


def _product_inputs():
    record = json.loads(json.dumps(profile.authority()))
    raws = {name: profile.reviewed_bytes("task-packets/%s.yaml" % name) for name in profile.PRODUCT_PACKETS}
    return raws, record


def test_v2_the_product_holds_its_facts():
    raws, record = _product_inputs()
    assert profile.check_products(raws, record) is None
    assert profile.validate_products() is None
    assert _sha(raws[LAB]) == record["productPackets"][LAB] and record["productComparators"] == {}
    assert profile.PRODUCT_FACTS[LAB]["predecessors"] == () and profile.PRODUCT_FACTS[LAB]["mainPin"] == "cc92594d6daa"


@pytest.mark.parametrize("change", ["missing", "comparator_offered", "byte_appended", "repository", "predecessors",
                                    "extra_path", "main_pin", "runner_pin"])
def test_v2_the_product_rechecks_in_full(change):
    raws, record = _product_inputs()
    raw = raws[LAB]
    pin = profile.PRODUCT_FACTS[LAB]["mainPin"].encode()
    edits = {
        "repository": (b"repository: mas-harness-research-lab", b"repository: mas-harness-distribution", V2_FACTS),
        "predecessors": (b"predecessors: []", b"predecessors: [MET-VERIFY-007]", V2_FACTS),
        "extra_path": (b'"research/"]', b'"research/", "Makefile"]', V2_FACTS),
        "main_pin": (pin, b"0" * len(pin), V2_PINS),
        "runner_pin": (profile.RUNNER_SHA256.encode(), b"0" * 64, V2_PINS),
    }
    if change == "missing":
        raws, message = {}, V2_SET
    elif change == "comparator_offered":
        record["productComparators"][LAB] = {"packet": "MET-VERIFY-007", "sha256": "0" * 64}
        message = V2_SET
    elif change == "byte_appended":
        raws[LAB], message = raw + b"\n", V2_BYTES + LAB
    else:
        old, new, message = edits[change]
        assert raw.count(old) >= 1
        raws[LAB] = raw.replace(old, new)
        record["productPackets"][LAB] = _sha(raws[LAB])
        message += LAB
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.check_products(raws, record)


# R1-R7, the registration -------------------------------------------------------------------------------------------------

def _registration_raws():
    return {path: profile._verified(path) for path in profile.ERA_SHA256}


def test_r_the_registration_holds():
    assert profile.check_registration(_registration_raws()) is None
    assert profile.validate_registration() is None


@pytest.mark.parametrize("change", ["r1_registry", "r1_successor", "r2_record_pin", "r2_module_pin", "r2_schema", "r3_live", "r3_reader",
                                    "r3_successor_map", "r3_lazy", "r3_eager", "r4_extends", "r4_split", "r4_reader", "r5_order", "r5_reader",
                                    "r6_plan", "r7_adr", "r7_successor_path", "r7_count", "r1_placement",
                                    "r2_placement_pin", "r3_placement_lazy", "r7_placement", "r7_decision",
                                    "r7_constants", "d1_conftest", "d1_readiness"])
def test_r_the_registration_rechecks_in_full(change):
    raws = _registration_raws()
    edits = {
        "r1_registry": ("architecture/repositories.yaml", b"\n", b"\n\n", "R1 registry"),
        "r1_successor": (profile.SUCCESSOR_REGISTRY, b'"kind": "meta"', b'"kind": "product"', "R1 registry"),
        "r2_record_pin": (profile.SUCCESSOR_REGISTRY, b'"sha256": "', b'"sha256": "0', "R2 schema"),
        "r2_module_pin": (profile.SUCCESSOR_MODULE, b'REGISTRY_SCHEMA_SHA256 = "', b'REGISTRY_SCHEMA_SHA256 = "0', "R2 schema"),
        "r2_schema": (profile.SUCCESSOR_SCHEMA, b'"additionalProperties": false', b'"additionalProperties": true', "R2 schema"),
        "r3_live": ("scripts/validate_readiness.py", b'    "mas-harness-conformance-labs",\n}\n',
                    b'    "mas-harness-conformance-labs",\n    "mas-harness-research-lab",\n}\n', "R3 constants"),
        "r3_reader": ("scripts/language_placement.py", b"registration.composed_rows(", b"registration.composed_rowz(",
                      "R3 constants"),
        "r3_lazy": ("scripts/language_placement.py", b"os.path.lexists(root.joinpath(", b"os.path.exists(root.joinpath(",
                    "R3 constants"),
        "r3_eager": ("scripts/language_placement.py", b"\nimport importlib\n", b"\nimport importlib\nimport repository_registration\n",
                     "R3 constants"),
        "r3_successor_map": ("scripts/validate_architecture.py",
                             b'EXPECTED_SUCCESSOR_REPOSITORIES = {"research-lab": "mas-harness-research-lab"}',
                             b'EXPECTED_SUCCESSOR_REPOSITORIES = {}', "R3 constants"),
        "r4_extends": (profile.SUCCESSOR_RECORD, b'"clause": "R8 clause 2"', b'"clause": "R8"', "R4 successor record and function"),
        "r4_split": (profile.SUCCESSOR_RECORD, b'"fromSlot": 284', b'"fromSlot": 283', "R4 successor record and function"),
        "r4_reader": (profile.SUCCESSOR_MODULE, b"\ndef registry_rows(", b"\ndef registry_rowz(", "R4 successor record and function"),
        "r5_order": (LOCK, b"", b"", "R5 release lock"),
        "r5_reader": (LOCK, b"    repositories = registry_with_successors()\n", b"    repositories = ()\n", "R5 release lock"),
        "r6_plan": (profile.PLAN_13, b"\n", b"\n\n", "R6 plan"),
        "r7_adr": ("docs/adr/0001-repository-boundaries.md", b"exactly fourteen repositories", b"exactly thirteen repositories", "R7 ADRs and language placement"),
        "r7_successor_path": ("docs/adr/0001-repository-boundaries.md", b"`architecture/repository-registration/repositories.json`",
                              b"`architecture/repositories.yaml`", "R7 ADRs and language placement"),
        "r1_placement": (profile.SUCCESSOR_PLACEMENT, b'"decision": {', b'"note": 1, "decision": {', "R1 registry"),
        "r2_placement_pin": (profile.SUCCESSOR_MODULE, b'PLACEMENT_SCHEMA_SHA256 = "', b'PLACEMENT_SCHEMA_SHA256 = "0',
                             "R2 schema"),
        "r3_placement_lazy": ("scripts/language_placement.py", b"os.path.lexists(root.joinpath(*SUCCESSOR_PLACEMENT_PATH",
                              b"os.path.exists(root.joinpath(*SUCCESSOR_PLACEMENT_PATH", "R3 constants"),
        "r7_placement": (profile.SUCCESSOR_PLACEMENT, b'"rNumber": "R13"', b'"rNumber": "R14"',
                         "R7 ADRs and language placement"),
        "r7_decision": (profile.SUCCESSOR_PLACEMENT, b'"policy": "LANG-D1"', b'"policy": "LANG-D2"',
                        "R7 ADRs and language placement"),
        "r7_constants": ("scripts/language_placement.py", b'\n    "research-lab": ("PYTHON",),\n', b"\n",
                         "R7 ADRs and language placement"),
        "r7_count": ("scripts/language_placement.py", b"\nREPOSITORY_COUNT = 13\n", b"\nREPOSITORY_COUNT = 14\n",
                     "R7 ADRs and language placement"),
        "d1_conftest": ("tests/conftest.py", b"        sys.setrecursionlimit(max(limit, 2000))\n",
                        b"        sys.setrecursionlimit(max(limit, 4000))\n", "D1 bounded raise"),
        "d1_readiness": ("scripts/validate_readiness.py", b"\nfinally:\n    sys.setrecursionlimit(_CHAIN_IMPORT_LIMIT)\n",
                         b"\nfinally:\n    pass\n",
                         "D1 bounded raise"),
    }
    path, old, new, label = edits[change]
    if change == "r5_order":
        lock = raws[LOCK]
        inert = b'    if document["documentKind"] == "INERT_LOCK":\n'
        at = lock.index(b"    repositories = registry_with_successors()\n")
        raws[LOCK] = lock[:at] + inert + b"        pass\n" + lock[at:].replace(inert, b"", 1)
    else:
        assert raws[path].count(old) >= 1, (path, old)
        raws[path] = raws[path].replace(old, new, 1)
    with pytest.raises(ValueError, match=re.escape("MET-REGISTRY-001 " + label)):
        profile.check_registration(raws)


# S, R8 clause 2's successor (CONTRACT_284 E8; C2-5) ----------------------------------------------------------------------

def _successor():
    import importlib.util
    spec = importlib.util.spec_from_file_location("_registration_s", profile.ROOT / profile.SUCCESSOR_MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    record_raw = profile.reviewed_bytes(profile.SUCCESSOR_RECORD)
    rule_raw = profile.reviewed_bytes(profile.V2_RULE)
    module_raw = profile.reviewed_bytes(profile.SUCCESSOR_MODULE)
    return module, record_raw, rule_raw, module_raw


def test_s_the_successor_rule_admits_the_name_from_slot_284():
    module, record_raw, rule_raw, module_raw = _successor()
    record = module.load(record_raw, rule_raw, module_raw)
    rule = json.loads(rule_raw)
    assert "mas-harness-research-lab" not in module.allowed_names(record, rule, 283)
    assert module.allowed_names(record, rule, 284)[-1] == "mas-harness-research-lab"
    assert len(module.allowed_names(record, rule, 284)) == 13


@pytest.mark.parametrize("change", ["below_284", "rule_digest", "module_digest", "v2_bytes"])
def test_s_the_successor_rule_refuses(change):
    module, record_raw, rule_raw, module_raw = _successor()
    record = module.load(record_raw, rule_raw, module_raw)
    if change == "below_284":
        assert "mas-harness-research-lab" not in module.allowed_names(record, json.loads(rule_raw), 283)
        return
    if change == "rule_digest":
        call = lambda: module.load(record_raw, rule_raw + b"\n", module_raw)
    elif change == "module_digest":
        call = lambda: module.load(record_raw, rule_raw, module_raw + b"\n")
    else:
        call = lambda: module.pin_v2(module, b"not v2")
    with pytest.raises(ValueError, match="registration"):
        call()

# S, the placement readers' clause (MON-284-D5A-RULE: the D5a oracle's two placement_rows cases) -------------------------

@pytest.mark.parametrize("change", ["record_without_schema", "record_a_directory"])
def test_s_placement_rows_refuse_an_unreadable_record_with_the_placement_clause(change, tmp_path):
    # A root holding the placement data and the successor placement record but not its schema, or a directory in the
    # record's place: placement_rows refuses, and its refusal carries the clause `placement`.
    module = _successor()[0]

    def put(rel, raw):
        target = tmp_path.joinpath(*rel.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    put(module.BASE_PLACEMENT_PATH, profile.reviewed_bytes(module.BASE_PLACEMENT_PATH))
    if change == "record_without_schema":
        put(module.SUCCESSOR_PLACEMENT_PATH, profile.reviewed_bytes(module.SUCCESSOR_PLACEMENT_PATH))
        missing = module.PLACEMENT_SCHEMA_PATH
    else:
        tmp_path.joinpath(*module.SUCCESSOR_PLACEMENT_PATH.split("/")).mkdir(parents=True)
        put(module.PLACEMENT_SCHEMA_PATH, profile.reviewed_bytes(module.PLACEMENT_SCHEMA_PATH))
        missing = module.SUCCESSOR_PLACEMENT_PATH
    with pytest.raises(module.Refused, match=re.escape("registration placement: %s cannot be read" % missing)):
        module.placement_rows(tmp_path)
