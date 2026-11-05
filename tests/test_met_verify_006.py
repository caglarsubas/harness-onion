"""Exact source lineage for MET-VERIFY-006; the fifth publishing step (DIST-005A-CTRL-FIX-004-PUBLISH, K = 2, with the exact-pair supersession closer): the head keeps the full fan-in (8 own and 90 predecessor routes, every catalog walk and round trip, the full payload loop), and the semantic check (V1-V9) has a failing case for every refusal, each on plain data, beside the closer's refusal vectors, CL-1's vectors and the productComparators F9 vector."""
import ast
import json
from copy import deepcopy
import os
import re
import stat
from pathlib import Path
from types import MappingProxyType

import pytest

from scripts import validate_met_verify_006 as profile
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
    # The newer MET-PERF-046 layer is projected away before this layer's payload checks.
    return profile.successor.historical_catalog(packets())


def changed_test():
    return next(path for path in profile._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert profile.validate() is None
    current = packets()
    accepted = profile.historical_catalog(current)
    assert len(current) == 287 and len(accepted) == 283
    assert set(accepted) == set(current) - {profile.NEW_PACKET, *profile.PRODUCT_PACKETS, profile.successor.NEW_PACKET}
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


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "sec5_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = profile.historical_bytes(path, raw) if route in ("current_test", "old_bytes") else None
    current_packets = packets() if route == "catalog" else None
    layer = layer_packets() if route == "payloads" else None
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
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
    with pytest.raises(ValueError, match="dist 005a ctrl fix 004 publish history authority digest"):
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
    assert len(profile.historical_catalog(current)) == 283


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
    assert len(profile.historical_catalog(current)) == 283
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
    assert len(rules) == 286 and len(parsed) == 285
    assert profile._packet_rules() is rules and len(parsed) == 285
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
    with pytest.raises(ValueError, match="dist 005a ctrl fix 004 publish history authority digest"):
        profile.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = layer_packets()
    profile.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "dist-005a-ctrl-fix-004-publish-authority.json").write_bytes(
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
    # The newer MET-PERF-046 layer refuses a mutated validator before this layer.
    with pytest.raises(ValueError, match="unreviewed current source: scripts/validate_met_verify_006.py"):
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
            assert all("validate_" not in alias.name or alias.name == "validate_met_perf_046"
                       for alias in node.names)


def _count_authority_reads(monkeypatch):
    counts = {}
    for module in (profile.successor, profile, sec5, perf45, sec4, vf5, sec3, cpp, adopt6, ev12, perf43, gov5, adopt5, gov4, ml8, pod2, ml9, lpka, lpi, lkg, pks, rrv, pod, evs, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner):
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
    expected = {module.__name__: 1 for module in (profile.successor, profile, sec5, perf45, sec4, vf5, sec3, cpp, adopt6, ev12, perf43, gov5, adopt5, gov4, ml8, pod2, ml9, lpka, lpi, lkg, pks, rrv, pod, evs, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner)}
    if route == "current_test":
        # The forward route reads this layer's newest bytes and then projects them forward once more.
        assert all(counts[name] >= 1 for name in expected) and set(counts) == set(expected)
    else:
        assert counts == expected


# MET-VERIFY-006 (DIST-005A-CTRL-FIX-004-PUBLISH): this era's check, and a failing case for every check. Every mutant
# below is applied to plain data handed to the layer's pure checks: nothing in the layer, the model or the library is
# patched or swapped, except the closer's byte vector, which changes the reader the way the scaffold's changed_reader
# tests do. The mutants are built by the pure helpers _<area>_mutant(change), one change name per mutant. The only chain
# file among the era's files is the dispatch chain whose outermost closer this layer adds
# (scripts/validate_conformance_reference_measurement.py). The head may not import scripts/validate_packet_ownership.py
# or the dispatch chain; this test loads them (a test may) and feeds their live results to the layer's pure checks, as
# 275 and 278 did. The closer (close_superseded_successor_overlaps) gets its four refusal vectors and CL-1's five.

VALIDATE = profile.validate_met_verify_006
OWN_PATH = "task-packets/MET-VERIFY-006.yaml"
PRODUCTS = ("DIST-005A", "CTRL-FIX-004")
PLAN04, PLAN11 = "docs/repositories/04-mas-harness-control-plane.md", "docs/repositories/11-mas-harness-distribution.md"
PLAN00 = "docs/repositories/00-harness-engineering.md"
OTHER_PATH = "scripts/validate_met_gov_005.py"
PACKET_BRIEF_SHA256 = "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274"
CLOSER_REFUSAL = "missing or changed closed superseded-successor dispatch"
# Each of V1-V9 and the tests that make it fail.
V_TESTS = {
    "V1": ("test_v1_the_products_bytes_equal_their_pinned_digests", "test_v1_the_products_facts_are_the_frozen_ones",
           "test_v1_dist_005a_is_dist_005_with_six_edits", "test_v1_ctrl_fix_004_keeps_ctrl_transport_001s_key_order"),
    "V2": ("test_v2_the_meta_packets_allowed_paths_name_both_products", "test_v2_each_plan_is_the_base_plus_its_item",
           "test_v2_this_repositorys_plan_holds_the_meta_item_once"),
    "V3": ("test_v3_the_registry_differs_from_the_base_by_exactly_the_one_rider",),
    "V4": ("test_v4_the_pair_list_keys_20_exact_messages", "test_v4_the_products_add_exactly_the_20_listed_diagnostics",
           "test_v4_the_two_allowed_strings_cover_exactly_12_and_8", "test_v4_the_dispatch_chain_closes_everything",
           "test_v4_the_closer_is_the_outermost_call_of_the_dispatch_chain",
           "test_v4_the_closer_refuses_and_keeps_every_error"),
    "V5": ("test_v5_one_added_yaml_per_repository", "test_v5_one_yaml_carries_each_products_branch"),
    "V6": ("test_v6_product_comparators_pin_the_comparators", "test_v6_each_product_keeps_its_comparators_commands"),
    "V7": ("test_v7_the_superseded_yamls_and_r6_stay", "test_v7_the_decisions_record_and_the_v3_records"),
    "V8": ("test_v8_the_ownership_validator_is_the_bases",),
    "V9": ("test_v9_every_weight_is_its_computed_value",),
}


def _packets():
    """The live packets, read as validate() reads them (each file's bytes through the layer, parsed by safe_load)."""
    return {path.stem: profile.safe_load(profile.regular_bytes("task-packets/" + path.name))
            for path in sorted((profile.ROOT / "task-packets").glob("*.yaml"))}


def _one_byte(raw):
    """raw with its last byte changed."""
    return raw[:-1] + (b"\n" if raw[-1:] != b"\n" else b" ")


def _ownership():
    from scripts.validate_packet_ownership import validate_packet_ownership
    return validate_packet_ownership


def _dispatch():
    from scripts.validate_conformance_reference_measurement import validate_dispatch_ownership
    return validate_dispatch_ownership


def test_the_contract_holds_for_this_era():
    assert VALIDATE(_packets()) is None


def test_the_era_holds_the_products_the_plans_the_registry_the_records_and_the_chain():
    import hashlib
    assert profile.PRODUCT_PACKETS == PRODUCTS
    assert set(profile.ERA_SHA256) == {
        *("task-packets/%s.yaml" % name for name in (*PRODUCTS, "DIST-005", "CTRL-INTEGRATE-001", "DIST-TRANSPORT-001",
                                                     "CTRL-TRANSPORT-001")),
        PLAN04, PLAN11, PLAN00, profile.REGISTRY_PATH, profile.PACKET_BRIEF, profile.CHAIN_PATH, profile.V2_RULE_PATH,
        profile.OWNERSHIP_PATH, profile.PAIRS_PATH, profile.DECISIONS_PATH, *profile.V3_RECORDS, profile.WEIGHTS_PATH,
        profile.WEIGHTS_INPUTS_PATH}
    assert len(profile.ERA_SHA256) == 20
    # No test is pinned; the scripts are the dispatch chain this layer's closer joins and the ownership validator.
    assert sorted(path for path in profile.ERA_SHA256 if path.startswith(("scripts/", "tests/"))) == sorted(
        [profile.CHAIN_PATH, profile.OWNERSHIP_PATH])
    for path, expected in profile.ERA_SHA256.items():
        assert hashlib.sha256(profile.reviewed_bytes(path)).hexdigest() == expected
    # The products are published, not new files: the authority's productPackets pins the same bytes; the two records
    # are new files the authority pins (MON-279-DEC, MON-279-PAIRS); the weights table is a changed file.
    record = profile.authority()
    assert list(record["productPackets"]) == list(PRODUCTS)
    assert record["productPackets"] == {name: profile.ERA_SHA256["task-packets/%s.yaml" % name] for name in PRODUCTS}
    assert not {"task-packets/%s.yaml" % name for name in PRODUCTS} & (set(record["newFiles"]) | set(record["changedFiles"]))
    assert record["newFiles"][profile.PAIRS_PATH] == profile.PAIRS_SHA256 == profile.ERA_SHA256[profile.PAIRS_PATH]
    assert record["newFiles"][profile.DECISIONS_PATH] == profile.ERA_SHA256[profile.DECISIONS_PATH]
    assert record["newFiles"][profile.WEIGHTS_INPUTS_PATH] == profile.ERA_SHA256[profile.WEIGHTS_INPUTS_PATH]
    assert profile.ERA_SHA256[profile.WEIGHTS_INPUTS_PATH].startswith("bcbc2ec4")
    assert record["changedFiles"][profile.WEIGHTS_PATH]["afterSha256"] == profile.ERA_SHA256[profile.WEIGHTS_PATH]
    assert profile.PAIRS_SHA256.startswith("00e80307")
    assert len(record["baselinePackets"]) == 283 and not set(PRODUCTS) & set(record["baselinePackets"])
    assert record["productComparators"] == {name: dict(pin) for name, pin in profile.COMPARATORS.items()}
    # The registry's base digest, recomputed here from this layer's inverse of this era's registry, and the rider.
    registry_base = json.loads(profile._undo_this_layer(profile.REGISTRY_PATH, profile._verified(profile.REGISTRY_PATH)))
    canonical = json.dumps(registry_base, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    assert hashlib.sha256(canonical).hexdigest() == profile.REGISTRY_BASE_SHA256
    assert len(registry_base["briefs"]) == 26 - 1
    assert profile.RIDERS == (
        ("PACKET", "MET-VERIFY-006/packet", "architecture/review-briefs/REVIEW_BRIEF_PACKET.md", 1),)
    assert profile.ERA_SHA256[profile.PACKET_BRIEF] == PACKET_BRIEF_SHA256
    # The registry, this repository's plan, the chain and the weights table are this layer's changed era files,
    # projected away; the products, the plans c1 changed, the brief, the base files and the new records are not.
    assert {profile.REGISTRY_PATH, PLAN00, profile.CHAIN_PATH, profile.WEIGHTS_PATH} <= set(profile._PROJECTION_RULES)
    assert not ({profile.PACKET_BRIEF, profile.V2_RULE_PATH, profile.OWNERSHIP_PATH, profile.PAIRS_PATH,
                 profile.DECISIONS_PATH, profile.WEIGHTS_INPUTS_PATH, *profile.V3_RECORDS,
                 *("task-packets/%s.yaml" % name for name in PRODUCTS)}
                & set(profile._PROJECTION_RULES))


@pytest.mark.parametrize("path", sorted(profile.ERA_SHA256))
def test_every_era_file_is_bound_by_digest(path):
    raw = profile._verified(path)
    assert profile._era_bytes(path, raw) == raw
    for changed in (raw + b" ", bytearray(raw)):
        with pytest.raises(ValueError, match=re.escape("unreviewed DIST-005A-CTRL-FIX-004-PUBLISH source: " + path)):
            profile._era_bytes(path, changed)


def test_a_path_outside_the_era_is_refused_before_it_is_read():
    for path in (OTHER_PATH, OWN_PATH, profile.VALIDATOR_PATH, "tests/test_met_sector_005.py",
                 "task-packets/IND-BANK-002A.yaml", "task-packets/DIST-004.yaml", "scripts/chain_identity_v3.py",
                 "architecture/ind-bank-002a-publish-authority.json", "docs/MASTER_DEVELOPMENT_PLAN.md",
                 "architecture/chain-inheritance/vectors.json", None):
        with pytest.raises(ValueError, match="MET-VERIFY-006 reviewed bytes are bound: "):
            profile._verified(path)
        with pytest.raises(ValueError, match="MET-VERIFY-006 reviewed bytes are bound: "):
            profile._era_bytes(path, b"")


# V1, the products: their pinned bytes, frozen facts, DIST-005A's six edits and CTRL-FIX-004's key order ----------------

PRODUCT_DIGEST_MESSAGE = "the product's bytes equal its pinned digest: "
PRODUCT_FACTS_MESSAGE = "the product's facts are the frozen ones: "
PRODUCT_BYTES_CHANGES = ["one_byte_changed", "byte_appended", "truncated", "not_bytes", "bytearray"]
PRODUCT_FACTS_CHANGES = ["id", "repository", "branch", "predecessors_changed", "predecessors_added", "allowed_dropped",
                         "allowed_reordered", "allowed_duplicated", "argv_dropped", "argv_reordered", "prefetch_added",
                         "warm_source", "source_reuse", "main_pin_dropped", "not_dict"]
DIFF_MESSAGE = "DIST-005A is DIST-005's bytes with exactly the six counted edits"
KEY_ORDER_MESSAGE = "CTRL-FIX-004 keeps CTRL-TRANSPORT-001's key order"


def _raw(name):
    return profile._verified("task-packets/%s.yaml" % name)


def _product(name):
    return profile.safe_load(_raw(name))


def _product_bytes_mutant(name, change):
    raw = _raw(name)
    return {"one_byte_changed": _one_byte(raw), "byte_appended": raw + b" ", "truncated": raw[:-1],
            "not_bytes": raw.decode("utf-8"), "bytearray": bytearray(raw)}[change]


def _product_facts_mutant(name, change):
    """The product's packet with one change."""
    packet = _product(name)
    if change == "not_dict":
        return [packet]
    if change == "id":
        packet["id"] = name + "B"
    elif change == "repository":
        packet["repository"] = "mas-harness-operator"
    elif change == "branch":
        packet["branch"] = packet["branch"] + "-2"
    elif change == "predecessors_changed":
        packet["predecessors"] = ["DIST-005" if name == "DIST-005A" else "CTRL-INTEGRATE-001"]
    elif change == "predecessors_added":
        packet["predecessors"] = packet["predecessors"] + ["DIST-001"]
    elif change == "allowed_dropped":
        packet["allowedPaths"] = packet["allowedPaths"][:-1]
    elif change == "allowed_reordered":
        packet["allowedPaths"] = packet["allowedPaths"][1:] + packet["allowedPaths"][:1]
    elif change == "allowed_duplicated":
        packet["allowedPaths"] = packet["allowedPaths"][:-1] + packet["allowedPaths"][:1]
    elif change == "argv_dropped":
        packet["offlineAcceptanceCommands"] = packet["offlineAcceptanceCommands"][:-1]
    elif change == "argv_reordered":
        packet["offlineAcceptanceCommands"] = packet["offlineAcceptanceCommands"][::-1]
    elif change == "prefetch_added":
        packet["prefetchCommands"] = [["make", "prefetch"]]
    elif change == "warm_source":
        packet["warmSourceAccess"] = "ALLOWED"
    elif change == "source_reuse":
        packet["sourceReuse"] = ["x"]
    else:
        (pin,) = profile.PRODUCT_PINS[name]
        packet["contracts"] = [item.replace(pin, pin[:8]) for item in packet["contracts"]]
    return packet


@pytest.mark.parametrize("name", PRODUCTS)
@pytest.mark.parametrize("change", PRODUCT_BYTES_CHANGES)
def test_v1_the_products_bytes_equal_their_pinned_digests(name, change):
    assert profile.check_product_bytes(name, _raw(name)) is None
    with pytest.raises(ValueError, match=re.escape(PRODUCT_DIGEST_MESSAGE + name)):
        profile.check_product_bytes(name, _product_bytes_mutant(name, change))


@pytest.mark.parametrize("name", PRODUCTS)
@pytest.mark.parametrize("change", PRODUCT_FACTS_CHANGES)
def test_v1_the_products_facts_are_the_frozen_ones(name, change):
    assert profile.check_product_facts(name, _product(name)) is None
    with pytest.raises(ValueError, match=re.escape(PRODUCT_FACTS_MESSAGE + name)):
        profile.check_product_facts(name, _product_facts_mutant(name, change))


def test_v1_the_frozen_facts_are_the_designs():
    dist, ctrl = _product("DIST-005A"), _product("CTRL-FIX-004")
    assert dist["predecessors"] == ["DIST-TRANSPORT-001"] and dist["branch"] == "codex/dist-005a-repro-security"
    assert len(dist["allowedPaths"]) == 9 and "ci/targets/dist-005a.json" in dist["allowedPaths"]
    assert "ci/targets/dist-005.json" not in dist["allowedPaths"] and len(dist["offlineAcceptanceCommands"]) == 22
    assert ctrl["predecessors"] == ["CTRL-TRANSPORT-001"] and ctrl["branch"] == "codex/ctrl-fix-004-page-not-found-status"
    assert len(ctrl["allowedPaths"]) == 13 and "ci/targets/ctrl-fix-004.json" in ctrl["allowedPaths"]
    assert len(ctrl["offlineAcceptanceCommands"]) == 8 and dist["prefetchCommands"] == ctrl["prefetchCommands"] == []
    assert dict(profile.PRODUCT_PINS) == {"DIST-005A": ("e28ea6a2375b8e0dab0865c2bda1c824ab1ca340",),
                                          "CTRL-FIX-004": ("e46641d609cef2224b6f0069076d14e45d3d7f24",)}


@pytest.mark.parametrize("change", ["seventh_line", "line_dropped", "key_added", "key_order", "branch_unchanged"])
def test_v1_dist_005a_is_dist_005_with_six_edits(change):
    raw, base = _raw("DIST-005A"), _raw("DIST-005")
    assert profile.check_product_diff(raw, base) is None
    assert profile.DIFF_LINES == (1, 3, 5, 6, 9, 13) and len(profile.DIFF_KEYS) == 6
    lines = raw.decode("utf-8").split("\n")
    if change == "seventh_line":
        lines[10] = lines[10] + " "
    elif change == "line_dropped":
        del lines[14]
    elif change == "key_added":
        lines.insert(1, "extraKey: 1")
    elif change == "key_order":
        lines[1], lines[2] = lines[2], lines[1]
    else:
        old = [line for line in base.decode("utf-8").split("\n") if line.startswith("branch: ")]
        lines = [old[0] if line.startswith("branch: ") else line for line in lines]
    mutant = "\n".join(lines).encode("utf-8")
    with pytest.raises(ValueError, match=re.escape(DIFF_MESSAGE)):
        profile.check_product_diff(mutant, base)


@pytest.mark.parametrize("change", ["swapped", "key_added", "key_dropped", "not_dict"])
def test_v1_ctrl_fix_004_keeps_ctrl_transport_001s_key_order(change):
    packet, base = _product("CTRL-FIX-004"), _product("CTRL-TRANSPORT-001")
    assert profile.check_key_order(packet, base) is None
    keys = list(packet)
    if change == "swapped":
        keys[0], keys[1] = keys[1], keys[0]
        packet = {key: packet[key] for key in keys}
    elif change == "key_added":
        packet = dict(packet, extraKey=1)
    elif change == "key_dropped":
        packet = {key: packet[key] for key in keys[:-1]}
    else:
        packet = [packet]
    with pytest.raises(ValueError, match=re.escape(KEY_ORDER_MESSAGE)):
        profile.check_key_order(packet, base)


# V2, this packet's paths and the three plans ---------------------------------------------------------------------------

OWN_PATHS_MESSAGE = "the meta packet's allowedPaths names both products"
OWN_PATHS_CHANGES = ["dist_dropped", "ctrl_dropped", "not_dict"]
PLAN_MESSAGE = "the plan differs from the base by exactly its yes'd texts: "
PLAN_CHANGES = ["item_changed", "item_missing", "item_twice", "base_line_changed", "line_added", "inserts_short",
                "not_bytes"]
OWN_ITEM_MESSAGE = "this repository's plan holds the MET-VERIFY-006 item once, naming both products"
OWN_ITEM_CHANGES = ["item_changed", "item_missing", "item_twice", "product_not_named", "not_bytes"]


def _own_paths_mutant(change):
    packet = _packets()[profile.NEW_PACKET]
    if change == "not_dict":
        return [packet]
    gone = "task-packets/%s.yaml" % ("DIST-005A" if change == "dist_dropped" else "CTRL-FIX-004")
    packet["allowedPaths"] = [path for path in packet["allowedPaths"] if path != gone]
    return packet


@pytest.mark.parametrize("change", OWN_PATHS_CHANGES)
def test_v2_the_meta_packets_allowed_paths_name_both_products(change):
    assert profile.check_own_paths(_packets()[profile.NEW_PACKET]) is None
    with pytest.raises(ValueError, match=re.escape(OWN_PATHS_MESSAGE)):
        profile.check_own_paths(_own_paths_mutant(change))


def _plan_mutant(path, change):
    """(raw, inserts) with one change; the inserts are found in the mutant as the layer finds them."""
    raw = profile._verified(path)
    text = raw.decode("utf-8")
    first = profile.plan_inserts(path, raw)[0]
    if change == "item_changed":
        text = text.replace(first, first.replace("`: ", "`:  ", 1), 1)
    elif change == "item_missing":
        text = text.replace(first, "", 1)
    elif change == "item_twice":
        text = text.replace(first, first + first, 1)
    elif change == "base_line_changed":
        text = text.replace("\n", "\n ", 1)
    elif change == "line_added":
        text = text + "x\n"
    if change == "not_bytes":
        return text, profile.plan_inserts(path, raw)
    mutant = text.encode("utf-8")
    inserts = profile.plan_inserts(path, mutant)
    return mutant, (inserts[:-1] if change == "inserts_short" else inserts)


@pytest.mark.parametrize("path", [PLAN04, PLAN11])
@pytest.mark.parametrize("change", PLAN_CHANGES)
def test_v2_each_plan_is_the_base_plus_its_item(path, change):
    raw = profile._verified(path)
    inserts = profile.plan_inserts(path, raw)
    assert len(inserts) == 1 and all(inserts)
    assert profile.check_plan(path, raw, inserts) is None
    with pytest.raises(ValueError, match=re.escape(PLAN_MESSAGE + path)):
        profile.check_plan(path, *_plan_mutant(path, change))


def test_v2_the_items_are_r04s_and_r11s_own_lines():
    (item13,) = profile.plan_inserts(PLAN04, profile._verified(PLAN04))
    (item10,) = profile.plan_inserts(PLAN11, profile._verified(PLAN11))
    assert item13.startswith("13. `CTRL-FIX-004-page-not-found-status`:") and item13.count("\n") == 1
    assert item10.startswith("10. `DIST-005A-repro-security`:") and item10.count("\n") == 1
    assert len(item13.encode("utf-8")) == 277 and len(item10.encode("utf-8")) == 330
    assert item10.count("`") == 2 and item13.count("`") == 2  # MON-279-READY: one packet token each


def _own_item_mutant(change):
    raw = profile._verified(PLAN00)
    if change == "not_bytes":
        return raw.decode("utf-8")
    text = raw.decode("utf-8")
    item = next(line for line in text.splitlines(keepends=True) if line.startswith(profile.OWN_ITEM_PREFIX))
    if change == "item_changed":
        text = text.replace(item, item.replace(": ", ":  ", 1), 1)
    elif change == "item_missing":
        text = text.replace(item, "", 1)
    elif change == "item_twice":
        text = text.replace(item, item + item, 1)
    else:
        text = text.replace(item, item.replace("CTRL-FIX-004", "CTRL-FIX-005"), 1)
    return text.encode("utf-8")


@pytest.mark.parametrize("change", OWN_ITEM_CHANGES)
def test_v2_this_repositorys_plan_holds_the_meta_item_once(change):
    assert profile.check_own_plan_item(profile._verified(PLAN00)) is None
    with pytest.raises(ValueError, match=re.escape(OWN_ITEM_MESSAGE)):
        profile.check_own_plan_item(_own_item_mutant(change))


# V3, the registry: the base plus exactly this packet's one rider -------------------------------------------------------

REGISTRY_MESSAGE = ("the registry differs from the base by exactly the MET-VERIFY-006 packet rider, pinning the generic "
                    "packet brief")
REGISTRY_CHANGES = ["rider_missing", "rider_twice", "rider_not_last", "rider_series", "rider_path", "rider_sha256",
                    "rider_version", "base_entry_changed", "base_entry_dropped", "not_json", "briefs_not_dict"]


def _registry():
    return json.loads(profile._verified(profile.REGISTRY_PATH))


def _briefs():
    return {profile.PACKET_BRIEF: profile._verified(profile.PACKET_BRIEF)}


def _registry_mutant(change):
    """(raw, briefs) with one change."""
    registry, briefs = _registry(), _briefs()
    rider = registry["briefs"][-1]
    if change == "not_json":
        return b"{", briefs
    if change == "briefs_not_dict":
        return json.dumps(registry).encode("utf-8"), [briefs]
    if change == "rider_missing":
        registry["briefs"] = registry["briefs"][:-1]
    elif change == "rider_twice":
        registry["briefs"] = registry["briefs"] + [dict(rider)]
    elif change == "rider_not_last":
        registry["briefs"] = [rider] + registry["briefs"][:-1]
    elif change == "rider_series":
        rider["series"] = "MET-VERIFY-006/contract"
    elif change == "rider_path":
        rider["path"] = "architecture/review-briefs/REVIEW_BRIEF_CONTRACT.md"
    elif change == "rider_sha256":
        rider["sha256"] = rider["sha256"][:-1] + ("0" if rider["sha256"][-1] != "0" else "1")
    elif change == "rider_version":
        rider["version"] = 2
    elif change == "base_entry_changed":
        registry["briefs"][0]["version"] = registry["briefs"][0]["version"] + 1
    else:
        registry["briefs"] = registry["briefs"][1:]
    return json.dumps(registry).encode("utf-8"), briefs


@pytest.mark.parametrize("change", REGISTRY_CHANGES)
def test_v3_the_registry_differs_from_the_base_by_exactly_the_one_rider(change):
    assert profile.check_registry(profile._verified(profile.REGISTRY_PATH), _briefs()) is None
    with pytest.raises(ValueError, match=re.escape(REGISTRY_MESSAGE)):
        profile.check_registry(*_registry_mutant(change))


# V4, ownership: 139 raw (119 + the 20 listed), the coverage strings, the dispatch closes all, the closer -----------------

PAIRS_MESSAGE = "the pair list keys 20 exact messages by the four listed packets"
PAIRS_CHANGES = ["pair_dropped", "message_twice", "wrong_sha", "no_product", "overlap_not_in_message", "fifth_packet",
                 "not_dict"]
OWNERSHIP_MESSAGE = "the products add exactly the 20 listed ownership diagnostics: 139, none other naming them"
OWNERSHIP_CHANGES = ["listed_missing", "listed_twice", "product_named", "count_extra", "messages_short", "not_list",
                     "not_str"]
COVERAGE_MESSAGE = "the two allowed-list strings cover exactly the 12 and 8 listed messages"
COVERAGE_CHANGES = ["ctrl_outside", "dist_outside", "messages_short", "not_list"]
DISPATCH_MESSAGE = "the dispatch chain closes every ownership diagnostic"
POSITION_MESSAGE = "close_superseded_successor_overlaps is the outermost closer of validate_dispatch_ownership"
POSITION_CHANGES = ["inner", "missing", "twice", "other_inner", "not_python", "not_bytes"]


def _pairs():
    return json.loads(profile._verified(profile.PAIRS_PATH))


def _pairs_mutant(change):
    import copy
    record = copy.deepcopy(_pairs())
    pairs = record["pairs"]
    if change == "not_dict":
        return [record]
    if change == "pair_dropped":
        record["pairs"] = pairs[:-1]
    elif change == "message_twice":
        pairs[1]["message"] = pairs[0]["message"]
    elif change == "wrong_sha":
        pairs[0]["packets"][0]["sha256"] = "0" * 64
    elif change == "no_product":
        pairs[0]["packets"] = [{"id": "DIST-005", "sha256": profile.PAIR_PACKETS["DIST-005"]},
                               {"id": "CTRL-INTEGRATE-001", "sha256": profile.PAIR_PACKETS["CTRL-INTEGRATE-001"]}]
    elif change == "overlap_not_in_message":
        pairs[0]["overlap"] = pairs[0]["overlap"] + ["docs/elsewhere.md"]
    else:
        pairs[0]["packets"][1] = {"id": "CTRL-INTEGRATE-002", "sha256": "1" * 64}
    return record


@pytest.mark.parametrize("change", PAIRS_CHANGES)
def test_v4_the_pair_list_keys_20_exact_messages(change):
    record = _pairs()
    assert profile.check_pairs(record) is None
    assert len(record["pairs"]) == 20 and record["closes"] == 20
    assert record["noPredecessorSemantics"] == (
        "no entry states that CTRL-FIX-004 supersedes or succeeds CTRL-INTEGRATE-001; each reason names only the "
        "superseded id and that id's own successor")
    with pytest.raises(ValueError, match=re.escape(PAIRS_MESSAGE)):
        profile.check_pairs(_pairs_mutant(change))


def _ownership_mutant(change):
    diagnostics, messages = _ownership()(_packets()), profile.pair_messages()
    if change == "listed_missing":
        return [item for item in diagnostics if item != messages[0]], messages
    if change == "listed_twice":
        return [item for item in diagnostics if item != diagnostics[0] or item in messages] + [messages[0]], messages
    if change == "product_named":
        return diagnostics[:-1] + ["packet DIST-005A overlaps a test probe"], messages
    if change == "count_extra":
        return diagnostics + ["a probe diagnostic naming no product"], messages
    if change == "messages_short":
        return diagnostics, messages[:-1]
    if change == "not_list":
        return tuple(diagnostics), messages
    return diagnostics[:-1] + [1], messages


@pytest.mark.parametrize("change", OWNERSHIP_CHANGES)
def test_v4_the_products_add_exactly_the_20_listed_diagnostics(change):
    live, messages = _ownership()(_packets()), profile.pair_messages()
    assert len(live) == profile.OWNERSHIP_COUNT == 139 and len(messages) == 20
    assert len([item for item in live if item not in messages]) == 119
    assert profile.check_ownership(live, messages) is None
    with pytest.raises(ValueError, match=re.escape(OWNERSHIP_MESSAGE)):
        profile.check_ownership(*_ownership_mutant(change))


def _coverage_mutant(change):
    diagnostics, messages = _ownership()(_packets()), profile.pair_messages()
    if change == "ctrl_outside":
        return diagnostics + ["probe: CTRL-FIX-004 and CTRL-INTEGRATE-001 elsewhere"], messages
    if change == "dist_outside":
        return diagnostics + ["probe: DIST-005 and DIST-005A elsewhere"], messages
    if change == "messages_short":
        return diagnostics, tuple(item for item in messages if "DIST-005 and DIST-005A" not in item)[:-1] + tuple(
            item for item in messages if "DIST-005 and DIST-005A" in item)
    return tuple(diagnostics), messages


@pytest.mark.parametrize("change", COVERAGE_CHANGES)
def test_v4_the_two_allowed_strings_cover_exactly_12_and_8(change):
    live, messages = _ownership()(_packets()), profile.pair_messages()
    assert dict(profile.PAIR_STRINGS) == {"CTRL-FIX-004 and CTRL-INTEGRATE-001": 12, "DIST-005 and DIST-005A": 8}
    assert profile.check_pair_coverage(live, messages) is None
    with pytest.raises(ValueError, match=re.escape(COVERAGE_MESSAGE)):
        profile.check_pair_coverage(*_coverage_mutant(change))


@pytest.mark.parametrize("closed", [["x"], None, ("x",)])
def test_v4_the_dispatch_chain_closes_everything(closed):
    assert _dispatch()(_packets()) == []
    assert profile.check_dispatch(_dispatch()(_packets())) is None
    with pytest.raises(ValueError, match=re.escape(DISPATCH_MESSAGE)):
        profile.check_dispatch(closed)


def _position_mutant(change):
    raw = profile._verified(profile.CHAIN_PATH)
    if change == "not_bytes":
        return raw.decode("utf-8")
    text = raw.decode("utf-8")
    outer = "close_superseded_successor_overlaps(packets, close_bootstrap_transport_dispatch(packets, "
    assert text.count(outer) == 1
    if change == "inner":
        text = text.replace(outer, "close_bootstrap_transport_dispatch(packets, close_superseded_successor_overlaps(packets, ")
    elif change == "missing":
        text = text.replace(outer, "(close_bootstrap_transport_dispatch(packets, ")
    elif change == "twice":
        text = text.replace(outer, "close_superseded_successor_overlaps(packets, " + outer)
        lines = text.splitlines(keepends=True)
        index = next(i for i, line in enumerate(lines) if outer in line)
        lines[index] = lines[index].rstrip("\n") + ")\n"
        text = "".join(lines)
    elif change == "other_inner":
        text = text.replace(outer, "close_superseded_successor_overlaps(packets, close_traversal_dispatch(packets, ")
    else:
        text = text + "\nreturn (\n"
    return text.encode("utf-8")


@pytest.mark.parametrize("change", POSITION_CHANGES)
def test_v4_the_closer_is_the_outermost_call_of_the_dispatch_chain(change):
    assert profile.check_closer_position(profile._verified(profile.CHAIN_PATH)) is None
    with pytest.raises(ValueError, match=re.escape(POSITION_MESSAGE)):
        profile.check_closer_position(_position_mutant(change))


def test_v4_the_closer_removes_exactly_the_20():
    packets, live = _packets(), _ownership()(_packets())
    closed = profile.close_superseded_successor_overlaps(packets, live)
    assert len(closed) == 119 and not set(closed) & set(profile.pair_messages())
    assert closed == [item for item in live if item not in profile.pair_messages()]


CLOSER_CHANGES = ["errors_not_list", "product_missing", "message_absent", "message_twice", "second_application", "listed_parsed_changed",
                  "listed_bytes_changed"]


@pytest.mark.parametrize("change", CLOSER_CHANGES)
def test_v4_the_closer_refuses_and_keeps_every_error(change, monkeypatch):
    """The closer's own refusals (V006-C1-3's four vectors, a non-list input, and CL-1's in-memory and on-disk
    binding): each returns the errors unchanged plus the closer's refusal. Its reasons, one per line:
    "diagnostic list",
    "exact pair list",
    "exact listed packet",
    "exact single superseded-successor overlaps"."""
    import copy
    packets, errors = copy.deepcopy(_packets()), _ownership()(_packets())
    messages = profile.pair_messages()
    if change == "errors_not_list":
        errors = tuple(errors)
    elif change == "product_missing":
        packets.pop("DIST-005A")
    elif change == "message_absent":
        errors = [item for item in errors if item != messages[3]]
    elif change == "message_twice":
        errors = errors + [messages[3]]
    elif change == "second_application":
        errors = profile.close_superseded_successor_overlaps(packets, errors)
    elif change == "listed_parsed_changed":
        packets["CTRL-INTEGRATE-001"]["objective"] = str(packets["CTRL-INTEGRATE-001"].get("objective")) + " probe"
    else:
        original = profile.regular_bytes
        path = "task-packets/DIST-005A.yaml"

        def changed_reader(name):
            raw = original(name)
            return raw.replace(b"repro", b"repr0", 1) if name == path else raw
        monkeypatch.setattr(profile, "regular_bytes", changed_reader)
    result = profile.close_superseded_successor_overlaps(packets, errors)
    assert result == list(errors) + [CLOSER_REFUSAL]


def _r_packet(packets, product, new_id):
    """A new packet of the product's repository, ordered after nothing, sharing one of the product's non-descriptor
    paths."""
    import copy
    packet = copy.deepcopy(packets[product])
    path = next(p for p in packet["allowedPaths"] if not p.startswith("ci/targets/"))
    packet.update(id=new_id, branch="codex/" + new_id.lower(), predecessors=[], allowedPaths=[path])
    return packet


@pytest.mark.parametrize("vector", ["twenty_first_overlap", "listed_bytes_changed", "dist_other_r11",
                                    "listed_parsed_changed", "outside_overlaps_ctrl"])
def test_cl1_the_generic_check_still_fires_outside_the_20(vector, monkeypatch):
    """CL-1's five vectors (CONTRACT_279 s5): each refuses, and every new raw diagnostic stays in the dispatch result."""
    import copy
    packets = copy.deepcopy(_packets())
    base = _ownership()(_packets())
    if vector == "twenty_first_overlap":
        extra = next(p for p in packets["CTRL-INTEGRATE-001"]["allowedPaths"]
                     if p not in packets["CTRL-FIX-004"]["allowedPaths"] and not p.startswith("ci/targets/"))
        packets["CTRL-FIX-004"]["allowedPaths"] = packets["CTRL-FIX-004"]["allowedPaths"] + [extra]
    elif vector == "listed_bytes_changed":
        original = profile.regular_bytes

        def changed_reader(name):
            raw = original(name)
            return raw.replace(b"page-not-found", b"page-not-f0und", 1) if name == "task-packets/CTRL-FIX-004.yaml" else raw
        monkeypatch.setattr(profile, "regular_bytes", changed_reader)
        result = profile.close_superseded_successor_overlaps(packets, base)
        assert result == base + [CLOSER_REFUSAL]
        return
    elif vector == "dist_other_r11":
        packets["DIST-099"] = _r_packet(packets, "DIST-005A", "DIST-099")
    elif vector == "listed_parsed_changed":
        packets["DIST-005"]["objective"] = str(packets["DIST-005"].get("objective")) + " probe"
    else:
        packets["CTRL-099"] = _r_packet(packets, "CTRL-FIX-004", "CTRL-099")
    raw = _ownership()(packets)
    new = [item for item in raw if item not in base]
    result = profile.close_superseded_successor_overlaps(packets, raw)
    assert result != [item for item in raw if item not in profile.pair_messages()] or new
    assert all(item in result for item in new)
    if vector in ("dist_other_r11", "outside_overlaps_ctrl"):
        assert new and all(("DIST-099" if vector == "dist_other_r11" else "CTRL-099") in item for item in new)
    else:
        assert CLOSER_REFUSAL in result


# V5, one added YAML per repository; one YAML per product branch --------------------------------------------------------

V5_MESSAGE = "one added YAML per repository"
V5_CHANGES = ["meta_repository", "duplicate_repository", "product_missing", "meta_missing", "not_dict"]
BRANCH_MESSAGE = "exactly one YAML carries each product's branch"


def _v5_mutant(change):
    packets = _packets()
    if change == "not_dict":
        return list(packets)
    if change == "meta_repository":
        packets[profile.NEW_PACKET]["repository"] = "mas-harness-operator"
    elif change == "duplicate_repository":
        packets["CTRL-FIX-004"]["repository"] = "mas-harness-distribution"
    elif change == "product_missing":
        packets.pop("DIST-005A")
    else:
        packets.pop(profile.NEW_PACKET)
    return packets


@pytest.mark.parametrize("change", V5_CHANGES)
def test_v5_one_added_yaml_per_repository(change):
    assert profile.check_one_per_repository(_packets()) is None
    assert dict(profile.ADDED_REPOSITORIES) == {"MET-VERIFY-006": "Harness-Engineering",
                                                "DIST-005A": "mas-harness-distribution",
                                                "CTRL-FIX-004": "mas-harness-control-plane"}
    with pytest.raises(ValueError, match=re.escape(V5_MESSAGE)):
        profile.check_one_per_repository(_v5_mutant(change))


@pytest.mark.parametrize("product", PRODUCTS)
@pytest.mark.parametrize("change", ["second_yaml", "branch_moved", "not_dict"])
def test_v5_one_yaml_carries_each_products_branch(product, change):
    import copy
    assert profile.check_branch_unique(_packets()) is None
    packets = copy.deepcopy(_packets())
    if change == "second_yaml":
        packets["DIST-005" if product == "DIST-005A" else "CTRL-INTEGRATE-001"]["branch"] = packets[product]["branch"]
    elif change == "branch_moved":
        packets[product]["branch"] = "codex/elsewhere"
    else:
        packets = list(packets)
    with pytest.raises(ValueError, match=re.escape(BRANCH_MESSAGE)):
        profile.check_branch_unique(packets)


# V6, the productComparators pins and the inheritance predicate; F9's list-packet vector ---------------------------------

COMPARATORS_MESSAGE = "productComparators pins each product's comparator"
INHERITANCE_MESSAGE = "the product keeps every command of its comparator in order: "


@pytest.mark.parametrize("change", ["stale_packet", "wrong_sha", "extra_key", "missing_one", "reordered", "not_dict"])
def test_v6_product_comparators_pin_the_comparators(change):
    value = {name: dict(pin) for name, pin in profile.authority()["productComparators"].items()}
    assert profile.check_comparators(value) is None
    assert {name: pin["packet"] for name, pin in value.items()} == {"DIST-005A": "DIST-TRANSPORT-001",
                                                                    "CTRL-FIX-004": "CTRL-TRANSPORT-001"}
    if change == "stale_packet":
        value["DIST-005A"]["packet"] = "DIST-005"
    elif change == "wrong_sha":
        value["CTRL-FIX-004"]["sha256"] = "0" * 64
    elif change == "extra_key":
        value["DIST-999"] = dict(value["DIST-005A"])
    elif change == "missing_one":
        value.pop("CTRL-FIX-004")
    elif change == "reordered":
        value = {"CTRL-FIX-004": value["CTRL-FIX-004"], "DIST-005A": value["DIST-005A"]}
    else:
        value = [value]
    with pytest.raises(ValueError, match=re.escape(COMPARATORS_MESSAGE)):
        profile.check_comparators(value)


@pytest.mark.parametrize("product", PRODUCTS)
@pytest.mark.parametrize("change", ["dropped", "reordered", "edited", "other_repository", "predecessor_changed"])
def test_v6_each_product_keeps_its_comparators_commands(product, change):
    import copy
    packet = _product(product)
    comparator = _product(profile.COMPARATORS[product]["packet"])
    assert profile.check_inheritance(product, packet, comparator) is None
    packet = copy.deepcopy(packet)
    argv = packet["offlineAcceptanceCommands"]
    if change == "dropped":
        del argv[0]
    elif change == "reordered":
        argv[0], argv[1] = argv[1], argv[0]
    elif change == "edited":
        argv[0] = argv[0][:-1] + ["PROBE=other"]
    elif change == "other_repository":
        packet["repository"] = "mas-harness-operator"
    else:
        packet["predecessors"] = ["DIST-005" if product == "DIST-005A" else "CTRL-INTEGRATE-001"]
    with pytest.raises(ValueError, match=re.escape(INHERITANCE_MESSAGE + product)):
        profile.check_inheritance(product, packet, comparator)


def test_f9_refuses_a_list_packet_in_product_comparators():
    """F9 (the authority's productComparators check): a pin whose packet is a list refuses as the authority's own
    'product comparators' refusal, never a TypeError."""
    record = json.loads(profile._checked_authority_raw())
    record["productComparators"] = {"DIST-005A": {"packet": ["DIST-TRANSPORT-001"],
                                                  "sha256": profile.COMPARATORS["DIST-005A"]["sha256"]}}
    with pytest.raises(ValueError, match="product comparators"):
        profile.require(type(record["productComparators"]) is dict
                        and all(type(pin) is dict and set(pin) == {"packet", "sha256"} and type(pin["packet"]) is str
                                and profile._sha(pin["sha256"])
                                and record["baselinePackets"].get(pin["packet"]) == pin["sha256"]
                                for pin in record["productComparators"].values()), "product comparators")


# V7, the superseded YAMLs, R6, the chain-inheritance records and the decisions record; V8; V9 --------------------------

SUPERSEDED_MESSAGE = "DIST-005 and CTRL-INTEGRATE-001 stay at their published bytes and R6 stays listed"
DECISIONS_MESSAGE = "the 279 decisions record holds its sections once, and the chain-inheritance records are unchanged"
OWNERSHIP_VALIDATOR_MESSAGE = "validate_packet_ownership is byte-identical to the base"
WEIGHTS_MESSAGE = "every weights-table entry equals its value computed from the pinned inputs"


@pytest.mark.parametrize("change", ["dist_changed", "ctrl_changed", "one_missing", "r6_dropped", "not_bytes"])
def test_v7_the_superseded_yamls_and_r6_stay(change):
    raws = {name: _raw(name) for name in profile.SUPERSEDED}
    rule = profile._verified(profile.V2_RULE_PATH)
    assert profile.check_superseded(raws, rule) is None
    assert dict(profile.SUPERSEDED) == {
        "DIST-005": "1cf1826b8c69c2030112899344577e0c5ea761b528eb978655cb098b29434d4f",
        "CTRL-INTEGRATE-001": "28441f4febf41c7228b516ca8f674785d28842aa6c3443f8fefebeb4a6e7de95"}
    if change == "dist_changed":
        raws["DIST-005"] = _one_byte(raws["DIST-005"])
    elif change == "ctrl_changed":
        raws["CTRL-INTEGRATE-001"] = _one_byte(raws["CTRL-INTEGRATE-001"])
    elif change == "one_missing":
        raws.pop("DIST-005")
    elif change == "r6_dropped":
        record = json.loads(rule)
        record["refusals"] = [r for r in record["refusals"] if r != "R6"]
        rule = json.dumps(record).encode("utf-8")
    else:
        raws["DIST-005"] = raws["DIST-005"].decode("utf-8")
    with pytest.raises(ValueError, match=re.escape(SUPERSEDED_MESSAGE)):
        profile.check_superseded(raws, rule)


@pytest.mark.parametrize("change", ["section_missing", "section_twice", "sections_swapped", "v3_rule_changed",
                                    "v3_record_missing", "not_bytes"])
def test_v7_the_decisions_record_and_the_v3_records(change):
    raw = profile._verified(profile.DECISIONS_PATH)
    records = {path: profile._verified(path) for path in profile.V3_RECORDS}
    assert profile.check_decisions(raw, records) is None
    text = raw.decode("utf-8")
    if change == "section_missing":
        text = text.replace("## Known debt\n", "## Known\n", 1)
    elif change == "section_twice":
        text = text + "\n## Known debt\n"
    elif change == "sections_swapped":
        text = text.replace("## MON-279-OWN2\n", "## SWAP\n", 1).replace("## MON-279-C1-SCOPE\n", "## MON-279-OWN2\n", 1)
        text = text.replace("## SWAP\n", "## MON-279-C1-SCOPE\n", 1)
    elif change == "v3_rule_changed":
        records["architecture/chain-inheritance/rule.json"] = _one_byte(records["architecture/chain-inheritance/rule.json"])
    elif change == "v3_record_missing":
        records.pop("architecture/chain-inheritance/decisions.md")
    mutant = text if change == "not_bytes" else text.encode("utf-8")
    with pytest.raises(ValueError, match=re.escape(DECISIONS_MESSAGE)):
        profile.check_decisions(mutant, records)


@pytest.mark.parametrize("change", ["one_byte", "not_bytes"])
def test_v8_the_ownership_validator_is_the_bases(change):
    raw = profile._verified(profile.OWNERSHIP_PATH)
    assert profile.check_ownership_validator(raw) is None
    with pytest.raises(ValueError, match=re.escape(OWNERSHIP_VALIDATOR_MESSAGE)):
        profile.check_ownership_validator(_one_byte(raw) if change == "one_byte" else raw.decode("utf-8"))


@pytest.mark.parametrize("change", ["entry_changed", "entry_dropped", "head_key_missing", "key_extra", "value_int",
                                    "head_entry_changed", "kappa_changed", "input_changed", "indent_two", "not_json"])
def test_v9_every_weight_is_its_computed_value(change):
    """MON-279-W5B: the table is the full refresh, every entry computed from the pinned inputs record."""
    raw, inputs_raw = profile._verified(profile.WEIGHTS_PATH), profile._verified(profile.WEIGHTS_INPUTS_PATH)
    assert profile.check_weights(raw, inputs_raw) is None
    table, inputs = json.loads(raw), json.loads(inputs_raw)
    assert len(table) == 185 and len(inputs["dryRunUs"]) == profile.WEIGHTS_BASE_COUNT == 182
    assert inputs["kappa"] == 1.0444 and sorted(inputs["headTests"]) == sorted(profile.WEIGHT_KEYS)
    assert {k: table[k] for k in profile.WEIGHT_KEYS} == {"tests/test_met_perf_045.py": 9.9,
                                                         "tests/test_met_sector_005.py": 23.7,
                                                         "tests/test_met_verify_006.py": 35.9}
    first = sorted(inputs["dryRunUs"])[0]
    if change == "entry_changed":
        table[first] = table[first] + 0.1
    elif change == "entry_dropped":
        table.pop(first)
    elif change == "head_key_missing":
        table.pop(profile.WEIGHT_KEYS[0])
    elif change == "key_extra":
        table["tests/test_probe.py"] = 1.0
    elif change == "value_int":
        table[profile.WEIGHT_KEYS[2]] = 36
    elif change == "head_entry_changed":
        table[profile.WEIGHT_KEYS[1]] = 23.8
    elif change == "kappa_changed":
        inputs["kappa"] = 1.0445
    elif change == "input_changed":
        inputs["dryRunUs"][first] = inputs["dryRunUs"][first] + 1000000
    if change == "not_json":
        mutant = b"{"
    elif change == "indent_two":
        mutant = (json.dumps(table, indent=2, sort_keys=True) + "\n").encode("utf-8")
    else:
        mutant = (json.dumps(table, indent=1, sort_keys=True) + "\n").encode("utf-8")
    mutant_inputs = (json.dumps(inputs, indent=1, sort_keys=True) + "\n").encode("utf-8")
    with pytest.raises(ValueError, match=re.escape(WEIGHTS_MESSAGE)):
        profile.check_weights(mutant, mutant_inputs)


def test_v9_the_full_refresh_moves_162_of_182_base_entries():
    """MON-279-W5B: against the base table (weights_276), 162 of the 182 entries change, summed |change| 446.5 s,
    base sum 3514.3 s -> 3393.0 s."""
    table = json.loads(profile._verified(profile.WEIGHTS_PATH))
    base = json.loads(profile._undo_this_layer(profile.WEIGHTS_PATH, profile._verified(profile.WEIGHTS_PATH)))
    assert len(base) == 182 and set(base) < set(table)
    changed = [k for k in base if table[k] != base[k]]
    assert len(changed) == 162
    assert round(sum(abs(table[k] - base[k]) for k in base), 1) == 446.5
    assert round(sum(base.values()), 1) == 3514.3 and round(sum(table[k] for k in base), 1) == 3393.0


# The canonical hunks: this layer's recorded inverse hunks are the canonical byte-minimal ones ------------------------

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

SEMANTIC_FUNCTIONS = {"_era_bytes", "_verified", "check_product_bytes", "check_product_facts", "check_product_diff",
                      "check_key_order", "check_own_paths", "check_plan", "check_own_plan_item", "check_registry",
                      "check_pairs", "check_ownership", "check_pair_coverage", "check_dispatch", "check_closer_position",
                      "close_superseded_successor_overlaps", "check_one_per_repository", "check_branch_unique",
                      "check_comparators", "check_inheritance", "check_superseded", "check_decisions",
                      "check_ownership_validator", "check_weights"}
CHECK_TESTS = {
    "MET-VERIFY-006 reviewed bytes are bound: ": "test_a_path_outside_the_era_is_refused_before_it_is_read",
    "unreviewed DIST-005A-CTRL-FIX-004-PUBLISH source: ": "test_every_era_file_is_bound_by_digest",
    PRODUCT_DIGEST_MESSAGE: "test_v1_the_products_bytes_equal_their_pinned_digests",
    PRODUCT_FACTS_MESSAGE: "test_v1_the_products_facts_are_the_frozen_ones",
    DIFF_MESSAGE: "test_v1_dist_005a_is_dist_005_with_six_edits",
    KEY_ORDER_MESSAGE: "test_v1_ctrl_fix_004_keeps_ctrl_transport_001s_key_order",
    OWN_PATHS_MESSAGE: "test_v2_the_meta_packets_allowed_paths_name_both_products",
    PLAN_MESSAGE: "test_v2_each_plan_is_the_base_plus_its_item",
    OWN_ITEM_MESSAGE: "test_v2_this_repositorys_plan_holds_the_meta_item_once",
    REGISTRY_MESSAGE: "test_v3_the_registry_differs_from_the_base_by_exactly_the_one_rider",
    PAIRS_MESSAGE: "test_v4_the_pair_list_keys_20_exact_messages",
    OWNERSHIP_MESSAGE: "test_v4_the_products_add_exactly_the_20_listed_diagnostics",
    COVERAGE_MESSAGE: "test_v4_the_two_allowed_strings_cover_exactly_12_and_8",
    DISPATCH_MESSAGE: "test_v4_the_dispatch_chain_closes_everything",
    POSITION_MESSAGE: "test_v4_the_closer_is_the_outermost_call_of_the_dispatch_chain",
    "diagnostic list": "test_v4_the_closer_refuses_and_keeps_every_error",
    "exact pair list": "test_v4_the_closer_refuses_and_keeps_every_error",
    "exact listed packet": "test_v4_the_closer_refuses_and_keeps_every_error",
    "exact single superseded-successor overlaps": "test_v4_the_closer_refuses_and_keeps_every_error",
    V5_MESSAGE: "test_v5_one_added_yaml_per_repository",
    BRANCH_MESSAGE: "test_v5_one_yaml_carries_each_products_branch",
    COMPARATORS_MESSAGE: "test_v6_product_comparators_pin_the_comparators",
    INHERITANCE_MESSAGE: "test_v6_each_product_keeps_its_comparators_commands",
    SUPERSEDED_MESSAGE: "test_v7_the_superseded_yamls_and_r6_stay",
    DECISIONS_MESSAGE: "test_v7_the_decisions_record_and_the_v3_records",
    OWNERSHIP_VALIDATOR_MESSAGE: "test_v8_the_ownership_validator_is_the_bases",
    WEIGHTS_MESSAGE: "test_v9_every_weight_is_its_computed_value",
    "unreviewed current source: ": "test_the_canonical_check_reads_this_eras_bytes",
    "canonical byte-minimal inverse hunks: ": "test_whole_line_hunks_are_refused_where_canonical_ones_differ"}
NAMED_MESSAGES = {PRODUCT_DIGEST_MESSAGE: "PRODUCT_DIGEST_MESSAGE", PRODUCT_FACTS_MESSAGE: "PRODUCT_FACTS_MESSAGE",
                  DIFF_MESSAGE: "DIFF_MESSAGE", KEY_ORDER_MESSAGE: "KEY_ORDER_MESSAGE",
                  OWN_PATHS_MESSAGE: "OWN_PATHS_MESSAGE", PLAN_MESSAGE: "PLAN_MESSAGE", OWN_ITEM_MESSAGE: "OWN_ITEM_MESSAGE",
                  REGISTRY_MESSAGE: "REGISTRY_MESSAGE", PAIRS_MESSAGE: "PAIRS_MESSAGE",
                  OWNERSHIP_MESSAGE: "OWNERSHIP_MESSAGE", COVERAGE_MESSAGE: "COVERAGE_MESSAGE",
                  DISPATCH_MESSAGE: "DISPATCH_MESSAGE", POSITION_MESSAGE: "POSITION_MESSAGE", V5_MESSAGE: "V5_MESSAGE",
                  BRANCH_MESSAGE: "BRANCH_MESSAGE", COMPARATORS_MESSAGE: "COMPARATORS_MESSAGE",
                  INHERITANCE_MESSAGE: "INHERITANCE_MESSAGE", SUPERSEDED_MESSAGE: "SUPERSEDED_MESSAGE",
                  DECISIONS_MESSAGE: "DECISIONS_MESSAGE", OWNERSHIP_VALIDATOR_MESSAGE: "OWNERSHIP_VALIDATOR_MESSAGE",
                  WEIGHTS_MESSAGE: "WEIGHTS_MESSAGE"}


def _refusal_messages():
    """The constant text of every refusal in the semantic check's functions and the canonical-hunk guard: a require or
    _bound call's message, cut at its first format field (adjacent string literals are one constant)."""
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
    parametrized expected messages, or the module constant that holds it); each of V1-V9 has its failing tests."""
    import inspect
    assert _refusal_messages() == set(CHECK_TESTS)
    for message, name in CHECK_TESTS.items():
        test = globals()[name]
        assert callable(test) and name.startswith("test_")
        source = inspect.getsource(test)
        assert (message[:40] in source or any(message.startswith(text) for text in _messages_of(name))
                or (message in NAMED_MESSAGES and NAMED_MESSAGES[message] in source)), message
    assert sorted(V_TESTS) == ["V1", "V2", "V3", "V4", "V5", "V6", "V7", "V8", "V9"]
    assert {name for names in V_TESTS.values() for name in names} == {
        name for name in CHECK_TESTS.values() if name.startswith("test_v")}
