"""Exact source lineage for MET-ADOPT-006; the first release profile (RELEASE-PROFILE-001): the record, its README, its model and its D5a oracle: the head keeps the full fan-in (8 own and 83 predecessor routes, every catalog walk and round trip, the full payload loop), and the semantic check (V1-V4: the five packet files and their pinned digests, the catalog pins taken from the model, the model accepting the record over the era's bytes and packet set, the oracle identity binding the oracle's bytes, the registry's MET-ADOPT-006 packet rider, and the canonical hunks) has a failing case for every refusal, each on plain data."""
import ast
import json
from copy import deepcopy
import os
import re
import stat
from pathlib import Path
from types import MappingProxyType

import pytest

from scripts import validate_release_profile as profile
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
    # The newer MET-PERF-044 layer is projected away before this layer's payload checks.
    return profile.successor.historical_catalog(packets())


def changed_test():
    return next(path for path in profile._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert profile.validate() is None
    current = packets()
    accepted = profile.historical_catalog(current)
    assert len(current) == 273 and len(accepted) == 271
    assert set(accepted) == set(current) - {profile.NEW_PACKET, profile.successor.NEW_PACKET}
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


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "ev12_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = profile.historical_bytes(path, raw) if route in ("current_test", "old_bytes") else None
    current_packets = packets() if route == "catalog" else None
    layer = layer_packets() if route == "payloads" else None
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
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
    with pytest.raises(ValueError, match="release profile history authority digest"):
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
    assert len(profile.historical_catalog(current)) == 271


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
    assert len(profile.historical_catalog(current)) == 271
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
    assert len(rules) == 272 and len(parsed) == 271
    assert profile._packet_rules() is rules and len(parsed) == 271
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
    with pytest.raises(ValueError, match="release profile history authority digest"):
        profile.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = layer_packets()
    profile.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "release-profile-authority.json").write_bytes(
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
    # The newer MET-PERF-044 layer refuses a mutated validator before this layer.
    with pytest.raises(ValueError, match="unreviewed current source: scripts/validate_release_profile.py"):
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
            assert all("validate_" not in alias.name or alias.name == "validate_chain_product_publish"
                       for alias in node.names)


def _count_authority_reads(monkeypatch):
    counts = {}
    for module in (profile.successor, profile, ev12, perf43, gov5, adopt5, gov4, ml8, pod2, ml9, lpka, lpi, lkg, pks, rrv, pod, evs, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner):
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
    expected = {module.__name__: 1 for module in (profile.successor, profile, ev12, perf43, gov5, adopt5, gov4, ml8, pod2, ml9, lpka, lpi, lkg, pks, rrv, pod, evs, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner)}
    if route == "current_test":
        # The forward route reads this layer's newest bytes and then projects them forward once more.
        assert all(counts[name] >= 1 for name in expected) and set(counts) == set(expected)
    else:
        assert counts == expected


# MET-ADOPT-006 (RELEASE-PROFILE-001): this era's check, and a failing case for every check. Every mutant below is
# applied to plain data handed to the layer's pure checks: nothing in the layer, the model or the library is patched or
# swapped. The mutants are built by the pure helpers _<area>_mutant(change), one change name per mutant; V2's mutants are
# readers that hand the model one changed file. No chain validator or chain test is among the era's files, the D5a
# oracle test is only hashed, and this file names no catalog: the layer binds the catalogs through the model's own pins.

VALIDATE = profile.validate_release_profile
# Tamper values name paths that already exist and that this packet does not carry in the tampered place.
OTHER_PATH = "scripts/validate_met_gov_005.py"
RP = "architecture/release-profile/"
PACKET_FILES = {"architecture/release-profile.json", RP + "README.md", RP + "oracle-identity.json",
                "scripts/release_profile.py", "tests/test_met_adopt_006_oracle.py"}
MODULES = {"scripts/sector_catalog.py", "scripts/safe_yaml.py"}
PACKET_BRIEF_SHA256 = "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274"
# Each of V1-V4 and the tests that make it fail.
V_TESTS = {
    "V1": ("test_v1_the_packet_files_are_exactly_the_five",
           "test_v1_each_packet_files_bytes_equal_its_pinned_digest"),
    "V2": ("test_v2_the_catalog_pins_are_the_models_own", "test_v2_the_model_refuses_a_changed_input"),
    "V3": ("test_v3_the_oracle_identity_names_the_oracle_test_and_is_kept",
           "test_v3_the_oracle_identitys_sha256_equals_the_oracle_tests_bytes"),
    "V4": ("test_v4_the_registry_differs_from_the_base_by_exactly_the_one_rider",),
}


def _packet_files():
    return {path: profile._verified(path) for path in profile.PACKET_FILES}


def _encoded(value):
    return (json.dumps(value, indent=1) + "\n").encode("utf-8")


def _flip(text):
    """A different lowercase hex digest of the same length."""
    return text[:-1] + ("0" if text[-1] != "0" else "1")


def _one_byte(raw):
    """raw with its last byte changed."""
    return raw[:-1] + (b"\n" if raw[-1:] != b"\n" else b" ")


def test_the_contract_holds_for_this_era():
    assert VALIDATE() is None


def test_the_era_holds_the_packet_files_the_model_inputs_the_registry_and_the_brief():
    import hashlib
    assert set(profile.PACKET_FILES) == PACKET_FILES and len(profile.PACKET_FILES) == 5
    assert MODULES <= set(profile.MODEL_INPUTS) and len(profile.MODEL_INPUTS) == 25
    assert len([path for path in profile.MODEL_INPUTS if path.startswith("task-packets/")]) == 18
    assert not any(path.startswith("task-packets/OP-") for path in profile.MODEL_INPUTS)
    assert set(profile.ERA_SHA256) == (PACKET_FILES | set(profile.MODEL_INPUTS)
                                       | {profile.REGISTRY_PATH, profile.PACKET_BRIEF})
    assert len(profile.ERA_SHA256) == 32
    # No chain validator and no chain test is pinned: the era's scripts are the model and the two modules it runs
    # with, and its test the D5a oracle.
    assert not any(path.startswith("scripts/validate_") for path in profile.ERA_SHA256)
    assert {path for path in profile.ERA_SHA256 if path.startswith("scripts/")} == {profile.MODEL_PATH} | MODULES
    assert {path for path in profile.ERA_SHA256 if path.startswith("tests/")} == {profile.ORACLE_TEST}
    for path, expected in profile.ERA_SHA256.items():
        assert hashlib.sha256(profile.reviewed_bytes(path)).hexdigest() == expected
    # The catalogs are bound by the model's own pins, never named here, and none is an era entry.
    pins = profile._catalog_pins()
    assert len(pins) == 3 and not set(pins) & set(profile.ERA_SHA256)
    for path, expected in pins.items():
        assert hashlib.sha256(profile.reviewed_bytes(path)).hexdigest() == expected
    # The oracle identity binds the oracle's bytes, read by this test's code.
    identity = json.loads(profile._verified(profile.ORACLE_IDENTITY))
    assert identity["file"] == {"path": profile.ORACLE_TEST, "sha256": profile.ERA_SHA256[profile.ORACLE_TEST]}
    assert identity["ruling"]["decision"] == "KEEP" and identity["ruling"]["ref"] == "MON-RP-ORACLE-KEEP"
    # The registry's base digest, recomputed here from this layer's inverse of this era's registry, and the rider.
    registry_base = json.loads(profile._undo_this_layer(profile.REGISTRY_PATH, profile._verified(profile.REGISTRY_PATH)))
    canonical = json.dumps(registry_base, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    assert hashlib.sha256(canonical).hexdigest() == profile.REGISTRY_BASE_SHA256
    assert len(registry_base["briefs"]) == 19 - 1
    assert profile.RIDERS == (("PACKET", "MET-ADOPT-006/packet", "architecture/review-briefs/REVIEW_BRIEF_PACKET.md", 1),)
    assert profile.ERA_SHA256[profile.PACKET_BRIEF] == PACKET_BRIEF_SHA256
    # The packet's files are new in this packet; the registry and the overlay module are this layer's changed era
    # files, projected away.
    assert PACKET_FILES <= set(profile.authority()["newFiles"])
    changed = {profile.REGISTRY_PATH, profile.OVERLAY_MODULE_PATH}
    assert changed <= set(profile._PROJECTION_RULES)
    assert not (set(profile.ERA_SHA256) - changed) & set(profile._PROJECTION_RULES)


@pytest.mark.parametrize("path", sorted(profile.ERA_SHA256))
def test_every_era_file_is_bound_by_digest(path):
    raw = profile._verified(path)
    assert profile._era_bytes(path, raw) == raw
    for changed in (raw + b" ", bytearray(raw)):
        with pytest.raises(ValueError, match=re.escape("unreviewed RELEASE-PROFILE-001 source: " + path)):
            profile._era_bytes(path, changed)


def test_a_path_outside_the_era_is_refused_before_it_is_read():
    for path in ("architecture/release-profile-v2.json", OTHER_PATH, profile.VALIDATOR_PATH,
                 "tests/test_release_profile.py", "task-packets/MET-ADOPT-006.yaml", "task-packets/OP-001.yaml",
                 "architecture/release-profile-authority.json", "architecture/evolution-surface/evolution-surface.json",
                 "docs/MASTER_DEVELOPMENT_PLAN.md", "architecture/sector-catalog/README.md", None):
        with pytest.raises(ValueError, match="MET-ADOPT-006 reviewed bytes are bound: "):
            profile._verified(path)
        with pytest.raises(ValueError, match="MET-ADOPT-006 reviewed bytes are bound: "):
            profile._era_bytes(path, b"")


# V1, the packet's files: exactly the five, each equal to its pinned digest --------------------------------------------

PACKET_MESSAGE = "the packet files are exactly the five"
PACKET_CHANGES = ["dropped", "extra", "renamed", "not_dict", "oracle_dropped", "model_dropped", "registry_added",
                  "brief_added", "module_added"]


def _packet_mutant(change):
    files = _packet_files()
    if change == "dropped":
        files.pop(RP + "README.md")
    elif change == "extra":
        files[OTHER_PATH] = profile.regular_bytes(OTHER_PATH)
    elif change == "renamed":
        files["scripts/release_profile_v2.py"] = files.pop(profile.MODEL_PATH)
    elif change == "not_dict":
        files = list(files.items())
    elif change == "oracle_dropped":
        files.pop(profile.ORACLE_TEST)
    elif change == "model_dropped":
        files.pop(profile.MODEL_PATH)
    elif change == "registry_added":
        files[profile.REGISTRY_PATH] = profile._verified(profile.REGISTRY_PATH)
    elif change == "brief_added":
        files[profile.PACKET_BRIEF] = profile._verified(profile.PACKET_BRIEF)
    else:
        files[profile.OVERLAY_MODULE_PATH] = profile._verified(profile.OVERLAY_MODULE_PATH)
    return files


@pytest.mark.parametrize("change", PACKET_CHANGES)
def test_v1_the_packet_files_are_exactly_the_five(change):
    profile.check_packet_files(_packet_files())
    with pytest.raises(ValueError, match=re.escape(PACKET_MESSAGE)):
        profile.check_packet_files(_packet_mutant(change))


@pytest.mark.parametrize("path", profile.PACKET_FILES)
@pytest.mark.parametrize("change", ["one_byte_changed", "byte_appended", "truncated", "not_bytes", "bytearray",
                                    "other_file", "none"])
def test_v1_each_packet_files_bytes_equal_its_pinned_digest(path, change):
    files = _packet_files()
    profile.check_packet_files(files)
    raw = files[path]
    if change == "one_byte_changed":
        files[path] = _one_byte(raw)
    elif change == "byte_appended":
        files[path] = raw + b" "
    elif change == "truncated":
        files[path] = raw[:-1]
    elif change == "not_bytes":
        files[path] = raw.decode("utf-8")
    elif change == "bytearray":
        files[path] = bytearray(raw)
    elif change == "other_file":
        files[path] = files[RP + "README.md" if path == profile.RECORD_PATH else profile.RECORD_PATH]
    else:
        files[path] = None
    with pytest.raises(ValueError, match=re.escape("a packet file's bytes equal its pinned digest: " + path)):
        profile.check_packet_files(files)


# V2, the model accepts the record: run from its verified bytes, over this era's reviewed bytes and packet set ---------

PINS_MESSAGE = "the model names and pins exactly three catalogs outside the era"
PINS_CHANGES = ["not_bytes", "not_python", "pins_dropped", "pin_dropped", "pin_added", "pin_not_hex", "pin_upper",
                "key_unresolved", "key_in_era", "not_a_dict"]


def _pins_mutant(change):
    raw = profile._verified(profile.MODEL_PATH)
    text = raw.decode("utf-8")
    start = text.index("BASE_SHA256 = {\n")
    end = text.index("}\n", start) + 2
    block = text[start:end]
    first = block.splitlines()[1]
    if change == "not_bytes":
        return text
    if change == "not_python":
        return raw + b"\n)\n"
    if change == "pins_dropped":
        return (text[:start] + text[end:]).encode("utf-8")
    if change == "pin_dropped":
        return text.replace(first + "\n", "", 1).encode("utf-8")
    if change == "pin_added":
        return text.replace(block, block.replace("}\n", '    "docs/README.md": "%s",\n}\n' % ("0" * 64)), 1).encode()
    if change == "pin_not_hex":
        return text.replace(first, first[:first.index('"') + 1] + "x" + first[first.index('"') + 2:], 1).encode()
    if change == "pin_upper":
        return text.replace(first, first.upper(), 1).encode("utf-8")
    if change == "key_unresolved":
        return text.replace(first, "    UNKNOWN_PATH" + first[first.index(":"):], 1).encode("utf-8")
    if change == "key_in_era":
        return text.replace(first, '    "%s"%s' % (profile.RECORD_PATH, first[first.index(":"):]), 1).encode("utf-8")
    return text.replace(block, "BASE_SHA256 = [\n" + block[len("BASE_SHA256 = {\n"):-2] + "]\n", 1).encode("utf-8")


@pytest.mark.parametrize("change", PINS_CHANGES)
def test_v2_the_catalog_pins_are_the_models_own(change):
    assert dict(profile.check_catalog_pins(profile._verified(profile.MODEL_PATH))) == dict(profile._catalog_pins())
    with pytest.raises(ValueError, match=re.escape(PINS_MESSAGE)):
        profile.check_catalog_pins(_pins_mutant(change))


MODEL_MESSAGE = "the release-profile model accepts the record over this era's bytes"
MODEL_CHANGES = ["record_byte", "record_appended", "overlay_byte", "sector_byte", "map_byte", "adoption_byte",
                 "catalog_byte", "registry_second_rider", "registry_byte", "packet_yaml_repository",
                 "packets_not_frozenset", "packet_unpublished", "notice_byte"]


def _model_reader(change):
    target, mutate = None, None
    catalog = sorted(profile._catalog_pins())[0]
    yamls = [path for path in profile.MODEL_INPUTS if path.startswith("task-packets/")]
    targets = {"record_byte": profile.RECORD_PATH, "record_appended": profile.RECORD_PATH,
               "overlay_byte": profile.MODEL_INPUTS[0], "sector_byte": profile.MODEL_INPUTS[1],
               "map_byte": profile.MODEL_INPUTS[2], "adoption_byte": profile.MODEL_INPUTS[3],
               "notice_byte": profile.MODEL_INPUTS[4], "catalog_byte": catalog,
               "registry_second_rider": profile.REGISTRY_PATH, "registry_byte": profile.REGISTRY_PATH,
               "packet_yaml_repository": yamls[0]}
    target = targets.get(change)
    # Each change alters what the model reads: the record and the adoption record are parsed as JSON, and the notice
    # is pinned by its section's digest (GO-272-MECH-FIX D1).
    if change == "record_appended":
        mutate = lambda raw: raw + b"x"
    elif change == "record_byte":
        def mutate(raw):
            member = b'"schemaVersion": ' + json.dumps(json.loads(raw)["schemaVersion"]).encode("utf-8")
            assert raw.count(member) == 1
            return raw.replace(member, member[:-1] + b'x"', 1)
    elif change == "adoption_byte":
        mutate = lambda raw: raw + b"x"
    elif change == "notice_byte":
        overlay = json.loads(profile._verified(profile.MODEL_INPUTS[0]))
        heading = overlay["distributionNotice"]["heading"].encode("utf-8")

        def mutate(raw):
            start = raw.index(b"\n" + heading + b"\n") + len(heading) + 2
            at = start + re.search(rb"[A-Za-z]", raw[start:]).start()
            assert b"\n## " not in raw[start:at]
            return raw[:at] + (b"x" if raw[at:at + 1] != b"x" else b"y") + raw[at + 1:]
    elif change == "registry_second_rider":
        def mutate(raw):
            registry = json.loads(raw)
            registry["briefs"].append(dict(registry["briefs"][-1]))
            return (json.dumps(registry, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
    elif change == "packet_yaml_repository":
        mutate = lambda raw: re.sub(rb"(?m)^repository: .*$", b"repository: mas-harness-operator", raw, count=1)
    elif target is not None:
        mutate = _one_byte

    def read(path):
        raw = profile._verified(path)
        return mutate(raw) if path == target else raw
    return read


def _model_packets(change):
    packets = profile._packet_set()
    if change == "packets_not_frozenset":
        return set(packets)
    if change == "packet_unpublished":
        record = json.loads(profile._verified(profile.RECORD_PATH))
        named = sorted(row["implementation"]["packetId"] for row in record["modules"] if "implementation" in row)
        return packets - {named[0]}
    return packets


def _model():
    return profile._era_release_profile()


def test_v2_the_model_accepts_this_eras_record():
    model = _model()
    assert type(model.check(profile._verified, profile._packet_set())) is dict
    profile.check_model(model, profile._verified, profile._packet_set())
    assert model.sector_catalog.__name__ == profile.OVERLAY_MODULE_NAME and model.__name__ == profile.MODEL_NAME


def test_v2_the_model_reads_this_eras_yaml_loader():
    # GO-272-P1-FIX: the model's `from scripts.safe_yaml import safe_load` resolves to this era's loader copy.
    assert _model().safe_load.__module__ == profile.LOADER_NAME


def test_v2_a_model_mapped_through_scripts_alone_reads_the_live_loader():
    # The failing case for the test above: with "scripts" as its only era name, the model's loader import is live.
    from types import SimpleNamespace

    era = {"scripts": SimpleNamespace(sector_catalog=_model().sector_catalog)}
    assert profile._era_model(profile.MODEL_PATH, profile.MODEL_NAME, era).safe_load.__module__ != profile.LOADER_NAME


@pytest.mark.parametrize("change", MODEL_CHANGES)
def test_v2_the_model_refuses_a_changed_input(change):
    model = _model()
    profile.check_model(model, profile._verified, profile._packet_set())
    with pytest.raises(ValueError, match=re.escape(MODEL_MESSAGE)):
        profile.check_model(model, _model_reader(change), _model_packets(change))


# V3, the oracle binding: the identity names the oracle test, is kept, and binds the oracle test's bytes -------------

ORACLE_NAMES_MESSAGE = "the oracle identity names the oracle test and its ruling is KEEP"
ORACLE_NAMES_CHANGES = ["not_bytes", "not_json", "not_dict", "schema", "schema_missing", "file_missing",
                        "file_not_dict", "path", "path_missing", "ruling_revised", "ruling_missing", "ruling_not_dict"]
ORACLE_DIGEST_MESSAGE = "the oracle identity's sha256 equals the oracle test's bytes"
ORACLE_DIGEST_CHANGES = ["sha_flipped", "sha_upper", "sha_short", "sha_missing", "sha_none", "oracle_bytes_changed",
                         "oracle_not_bytes", "oracle_other_file"]


def _oracle_names_mutant(change):
    raw = profile._verified(profile.ORACLE_IDENTITY)
    if change == "not_bytes":
        return raw.decode("utf-8")
    if change == "not_json":
        return raw + b"}"
    identity = json.loads(raw)
    if change == "not_dict":
        identity = [identity]
    elif change == "schema":
        identity["schemaVersion"] = "planeon.oracle-identity/v2"
    elif change == "schema_missing":
        del identity["schemaVersion"]
    elif change == "file_missing":
        del identity["file"]
    elif change == "file_not_dict":
        identity["file"] = [identity["file"]["path"], identity["file"]["sha256"]]
    elif change == "path":
        identity["file"]["path"] = "tests/test_language_placement_oracle.py"
    elif change == "path_missing":
        del identity["file"]["path"]
    elif change == "ruling_revised":
        identity["ruling"]["decision"] = "REVISE"
    elif change == "ruling_missing":
        del identity["ruling"]
    else:
        identity["ruling"] = "KEEP"
    return _encoded(identity)


@pytest.mark.parametrize("change", ORACLE_NAMES_CHANGES)
def test_v3_the_oracle_identity_names_the_oracle_test_and_is_kept(change):
    oracle_raw = profile._verified(profile.ORACLE_TEST)
    profile.check_oracle(profile._verified(profile.ORACLE_IDENTITY), oracle_raw)
    with pytest.raises(ValueError, match=re.escape(ORACLE_NAMES_MESSAGE)):
        profile.check_oracle(_oracle_names_mutant(change), oracle_raw)


@pytest.mark.parametrize("change", ORACLE_DIGEST_CHANGES)
def test_v3_the_oracle_identitys_sha256_equals_the_oracle_tests_bytes(change):
    identity_raw, oracle_raw = profile._verified(profile.ORACLE_IDENTITY), profile._verified(profile.ORACLE_TEST)
    profile.check_oracle(identity_raw, oracle_raw)
    identity = json.loads(identity_raw)
    if change == "sha_flipped":
        identity["file"]["sha256"] = _flip(identity["file"]["sha256"])
    elif change == "sha_upper":
        identity["file"]["sha256"] = identity["file"]["sha256"].upper()
    elif change == "sha_short":
        identity["file"]["sha256"] = identity["file"]["sha256"][:63]
    elif change == "sha_missing":
        del identity["file"]["sha256"]
    elif change == "sha_none":
        identity["file"]["sha256"] = None
    elif change == "oracle_bytes_changed":
        oracle_raw = oracle_raw + b"\n"
    elif change == "oracle_not_bytes":
        oracle_raw = bytearray(oracle_raw)
    else:
        oracle_raw = profile._verified(profile.MODEL_PATH)
    with pytest.raises(ValueError, match=re.escape(ORACLE_DIGEST_MESSAGE)):
        profile.check_oracle(_encoded(identity), oracle_raw)


# V4, the registry: the base plus exactly the one rider, appended last, pinning the generic packet brief ---------------

REGISTRY_MESSAGE = ("the registry differs from the base by exactly the MET-ADOPT-006 packet rider, pinning the generic "
                    "packet brief")
REGISTRY_CHANGES = ["second_rider", "pin_changed", "pin_zero", "rider_dropped", "rider_not_last", "rider_kind",
                    "rider_path", "rider_version", "rider_extra_key", "other_series", "base_entry_changed",
                    "base_entry_dropped", "base_entry_added", "top_level_added", "not_json", "not_bytes",
                    "duplicate_key", "brief_bytes", "brief_not_bytes", "brief_missing"]


def _briefs():
    return {profile.PACKET_BRIEF: profile._verified(profile.PACKET_BRIEF)}


def _registry_mutant(change):
    raw, briefs = profile._verified(profile.REGISTRY_PATH), _briefs()
    if change == "brief_bytes":
        return raw, {profile.PACKET_BRIEF: briefs[profile.PACKET_BRIEF] + b" "}
    if change == "brief_not_bytes":
        return raw, {profile.PACKET_BRIEF: briefs[profile.PACKET_BRIEF].decode("utf-8")}
    if change == "brief_missing":
        return raw, {}
    if change == "not_json":
        return raw.rstrip()[:-1], briefs
    if change == "not_bytes":
        return raw.decode("utf-8"), briefs
    if change == "duplicate_key":
        return b'{"briefs": [], ' + raw.lstrip()[1:], briefs
    registry = json.loads(raw)
    riders = [entry for entry in registry["briefs"] if entry["series"].startswith("MET-ADOPT-006/")]
    assert [entry["series"] for entry in riders] == ["MET-ADOPT-006/packet"]
    rider = riders[0]
    if change == "second_rider":
        registry["briefs"].append(dict(rider))
    elif change == "pin_changed":
        rider["sha256"] = _flip(rider["sha256"])
    elif change == "pin_zero":
        rider["sha256"] = "0" * 64
    elif change == "rider_dropped":
        registry["briefs"] = [entry for entry in registry["briefs"] if entry is not rider]
    elif change == "rider_not_last":
        registry["briefs"] = [rider] + [entry for entry in registry["briefs"] if entry is not rider]
    elif change == "rider_kind":
        rider["kind"] = "CONTRACT"
    elif change == "rider_path":
        rider["path"] = "architecture/review-briefs/REVIEW_BRIEF_CONTRACT.md"
    elif change == "rider_version":
        rider["version"] = 2
    elif change == "rider_extra_key":
        rider["note"] = "x"
    elif change == "other_series":
        registry["briefs"].append(dict(rider, series="MET-ADOPT-006/contract"))
    elif change == "base_entry_changed":
        registry["briefs"][0]["sha256"] = _flip(registry["briefs"][0]["sha256"])
    elif change == "base_entry_dropped":
        registry["briefs"] = registry["briefs"][1:]
    elif change == "base_entry_added":
        registry["briefs"].insert(0, dict(registry["briefs"][0], series="MET-ENFORCE-042/design"))
    else:
        registry["extra"] = 1
    return (json.dumps(registry, indent=1) + "\n").encode("utf-8"), briefs


@pytest.mark.parametrize("change", REGISTRY_CHANGES)
def test_v4_the_registry_differs_from_the_base_by_exactly_the_one_rider(change):
    raw, briefs = profile._verified(profile.REGISTRY_PATH), _briefs()
    profile.check_registry(raw, briefs)
    assert profile.check_registry((json.dumps(json.loads(raw), indent=2) + "\n").encode("utf-8"), briefs) is None
    registry = json.loads(raw)
    assert len(registry["briefs"]) == 19
    assert [row["series"] for row in registry["briefs"] if row["series"].startswith("MET-ADOPT-006")] == [
        "MET-ADOPT-006/packet"]
    with pytest.raises(ValueError, match=re.escape(REGISTRY_MESSAGE)):
        profile.check_registry(*_registry_mutant(change))


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

SEMANTIC_FUNCTIONS = {"check_catalog_pins", "_era_bytes", "_verified", "check_packet_files", "check_model",
                      "check_oracle", "check_registry"}
CHECK_TESTS = {
    PINS_MESSAGE: "test_v2_the_catalog_pins_are_the_models_own",
    "MET-ADOPT-006 reviewed bytes are bound: ": "test_a_path_outside_the_era_is_refused_before_it_is_read",
    "unreviewed RELEASE-PROFILE-001 source: ": "test_every_era_file_is_bound_by_digest",
    PACKET_MESSAGE: "test_v1_the_packet_files_are_exactly_the_five",
    "a packet file's bytes equal its pinned digest: ": "test_v1_each_packet_files_bytes_equal_its_pinned_digest",
    MODEL_MESSAGE: "test_v2_the_model_refuses_a_changed_input",
    ORACLE_NAMES_MESSAGE: "test_v3_the_oracle_identity_names_the_oracle_test_and_is_kept",
    ORACLE_DIGEST_MESSAGE: "test_v3_the_oracle_identitys_sha256_equals_the_oracle_tests_bytes",
    REGISTRY_MESSAGE: "test_v4_the_registry_differs_from_the_base_by_exactly_the_one_rider",
    "unreviewed current source: ": "test_the_canonical_check_reads_this_eras_bytes",
    "canonical byte-minimal inverse hunks: ": "test_whole_line_hunks_are_refused_where_canonical_ones_differ"}
NAMED_MESSAGES = {PINS_MESSAGE: "PINS_MESSAGE", PACKET_MESSAGE: "PACKET_MESSAGE", MODEL_MESSAGE: "MODEL_MESSAGE",
                  ORACLE_NAMES_MESSAGE: "ORACLE_NAMES_MESSAGE", ORACLE_DIGEST_MESSAGE: "ORACLE_DIGEST_MESSAGE",
                  REGISTRY_MESSAGE: "REGISTRY_MESSAGE"}


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
    parametrized expected messages, or the module constant that holds it); each of V1-V4 has its failing tests."""
    import inspect
    assert _refusal_messages() == set(CHECK_TESTS)
    for message, name in CHECK_TESTS.items():
        test = globals()[name]
        assert callable(test) and name.startswith("test_")
        source = inspect.getsource(test)
        assert (message[:40] in source or any(message.startswith(text) for text in _messages_of(name))
                or (message in NAMED_MESSAGES and NAMED_MESSAGES[message] in source)), message
    assert sorted(V_TESTS) == ["V1", "V2", "V3", "V4"]
    assert {name for names in V_TESTS.values() for name in names} == {
        name for name in CHECK_TESTS.values() if name.startswith("test_v")}


# The collection guard (Q-272-DRY-1 (a)): a test module's collection leaves sys.path as it found it -----------------------

def _collect_two_modules(tmp_path, guarded):
    """Two test modules collected in one nested session: the first appends a directory to sys.path at import, the second
    records sys.path at its own import and asserts the directory is absent. With `guarded`, the nested conftest binds
    the repository's tests/conftest.py hook, loaded by path; without it, the conftest is empty."""
    import subprocess
    import sys
    added = str(tmp_path / "added")
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    hook = ("import importlib.util\n"
            "_spec = importlib.util.spec_from_file_location('_repository_tests_conftest', %r)\n"
            "_repository = importlib.util.module_from_spec(_spec)\n"
            "_spec.loader.exec_module(_repository)\n"
            "pytest_make_collect_report = _repository.pytest_make_collect_report\n" % str(profile.ROOT / "tests/conftest.py"))
    (tmp_path / "conftest.py").write_text(hook if guarded else "", encoding="utf-8")
    (tmp_path / "test_a_appends.py").write_text("import sys\nsys.path.append(%r)\n\n\ndef test_a():\n    pass\n" % added,
                                               encoding="utf-8")
    (tmp_path / "test_b_sees.py").write_text("import sys\nSEEN = list(sys.path)\n\n\ndef test_b():\n    assert %r not in SEEN\n"
                                             % added, encoding="utf-8")
    command = [sys.executable, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--basetemp=%s" % (tmp_path / "bt"),
               "test_a_appends.py", "test_b_sees.py"]
    return subprocess.run(command, cwd=tmp_path, capture_output=True, text=True, timeout=120,
                          env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})


def test_the_collection_guard_restores_sys_path_for_the_next_module(tmp_path):
    result = _collect_two_modules(tmp_path, guarded=True)
    assert result.returncode == 0 and "2 passed" in result.stdout, result.stdout[-2000:]


def test_without_the_guard_the_next_module_sees_the_appended_directory(tmp_path):
    # The failing case for the test above: an empty conftest leaves the first module's directory for the second.
    result = _collect_two_modules(tmp_path, guarded=False)
    assert result.returncode == 1 and "1 failed, 1 passed" in result.stdout, result.stdout[-2000:]


# The model's own tests (RELEASE-PROFILE-001, candidates c1 to c5, adopted at c5; the MON-RP-C5-NOTES wording of one
# test name). Their module docstring, kept:
# The release profile record (RELEASE-PROFILE-001, MET-ADOPT-006): the real record passes check(read, packets), and
# every failing case of design E1 fails for its named refusal code. Operator packet YAMLs are never opened: the reader
# used here refuses any task-packets/OP-* path (its own literal prefix, not the module's), and two tests show the guard is
# live: the module's own guard stops an emptied operator set before any read, and with the module's guard bypassed the
# reader's guard fires. The reader supplies the registry with the MET-ADOPT-006/packet rider appended only when it is
# absent (RP-C1-4, MON-RP-MECH-i), so the same tests hold before and after the 272 mechanics add the rider. The catalogs
# reach the model only through this reader and packet set (Q-RP-PROJ (a1), design E2).
import copy
import json
import os
from pathlib import Path

import pytest

from scripts import release_profile as rp
from scripts import sector_catalog
from scripts.safe_yaml import safe_load

ROOT = Path(__file__).resolve().parents[1]


class OperatorRead(Exception):
    """Raised by the guarded reader if anything tries to open an operator packet YAML."""


FIXTURE_OPERATOR_PATH = "task-packets/OP-"


def _serialize(registry):
    return (json.dumps(registry, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def _registry(mutate=None, serialize=_serialize):
    registry = json.loads((ROOT / rp.BRIEFS_PATH).read_bytes())
    template = next(b for b in registry["briefs"] if b["series"] == rp.RIDER_TEMPLATE_SERIES)
    if not any(b["series"] == rp.RIDER_SERIES for b in registry["briefs"]):
        registry["briefs"].append(dict(template, series=rp.RIDER_SERIES))
    if mutate:
        mutate(registry["briefs"], template)
    return serialize(registry)


def _packets():
    return frozenset(name[:-5] for name in os.listdir(ROOT / "task-packets") if name.endswith(".yaml"))


def _reader(record=None, files=None, log=None):
    files = dict({rp.BRIEFS_PATH: _registry()}, **(files or {}))
    if record is not None:
        files[rp.RECORD_PATH] = (json.dumps(record, indent=2, ensure_ascii=False) + "\n").encode("utf-8")

    def read(path):
        if log is not None:
            log.append(path)
        if path.startswith(FIXTURE_OPERATOR_PATH):
            raise OperatorRead(path)
        if path in files:
            return files[path]
        assert not path.startswith("/") and ".." not in path.split("/")
        return (ROOT / path).read_bytes()
    return read


def _record():
    return json.loads((ROOT / rp.RECORD_PATH).read_bytes())


def _row(rec, node):
    return next(row for row in rec["modules"] if row["id"] == node)


def _fact(rec, node):
    return next(fact for fact in rec["tenantFacts"] if fact["id"] == node)


def _exclusion(rec, name):
    return next(row for row in rec["exclusions"] if row["component"] == name)


TENANT = "provider.runtime.infrastructure.kubernetes-upstream"
RETRIEVAL = "module.knowledge.retrieval-context.retrieval-service"
OPERATOR = "module.runtime.infrastructure.operator"
CONTRACTS = "module.platform.contracts"
POLICY = "module.trust.security.policy-decision"
PACK = "artifact.platform.industry-pack"


def test_the_real_record_passes_without_opening_an_operator_packet():
    summary = rp.check(_reader(), _packets())
    assert summary["modules"] == 30 and summary["tenantFacts"] == 11 and summary["closure"] == 41
    assert summary["in"] == 13 and summary["exclusions"] == 10 and summary["rider"] == 1
    assert summary["operatorRows"] == ["module.runtime.infrastructure.bundle-verifier",
                                       "module.runtime.infrastructure.namespace-baseline", OPERATOR]
    assert len(summary["citedRows"]) == 6


def test_the_registry_with_exactly_this_packets_rider_passes():
    assert rp.check(_reader(files={rp.BRIEFS_PATH: _registry()}), _packets())["rider"] == 1


def test_an_operator_packet_yaml_is_never_opened():
    with pytest.raises(ValueError, match=r"^RP_OWNER_PACKET: an operator packet YAML is never opened"):
        rp.packet_repository(_reader(), "OP-001")


def _set(path, value):
    def mutate(rec):
        target = rec
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
    return mutate


def _edit_row(node, fn):
    return lambda rec: fn(_row(rec, node))


def _edit_fact(node, fn):
    return lambda rec: fn(_fact(rec, node))


def _edit_exclusion(name, fn):
    return lambda rec: fn(_exclusion(rec, name))


def _swap_class(row):
    row["class"] = "CLOSURE" if row["class"] == "SELECTED" else "SELECTED"


def _relabel(row):
    row["rowClass"] = "TENANT_PLATFORM"
    del row["implementation"]
    row["attestationRef"] = "external.kubernetes-api"
    row.update({k: row.pop(k) for k in ("readiness", "exitEvidence")})


def _attestation_on_repository(row):
    del row["implementation"]
    row["attestationRef"] = "external.kubernetes-api"


def _drop_node(rec):
    rec["closure"]["nodes"].remove(RETRIEVAL)


def _add_excluded(rec):
    rec["closure"]["nodes"] = sorted(rec["closure"]["nodes"] + ["provider.planeon.ollama"])


def _drop_module_row(rec):
    rec["modules"] = [row for row in rec["modules"] if row["id"] != RETRIEVAL]


def _extra_module_row(rec):
    extra = copy.deepcopy(_row(rec, RETRIEVAL))
    extra["id"] = "provider.planeon.ollama"
    rec["modules"] = sorted(rec["modules"] + [extra], key=lambda row: row["id"])


def _duplicate_module_row(rec):
    index = next(i for i, row in enumerate(rec["modules"]) if row["id"] == RETRIEVAL)
    rec["modules"].insert(index, copy.deepcopy(rec["modules"][index]))


def _h10_to_deferred(rec):
    row = next(r for r in rec["providerSet"]["in"] if r["key"] == "H10")
    rec["providerSet"]["in"].remove(row)
    rec["providerSet"]["deferred"].append({"key": "H10", "harness": row["harness"], "reason": "moved"})


def _drop_platform(name):
    def mutate(rec):
        rec["providerSet"]["platformNonHarness"].remove(name)
    return mutate


def _excluded_in_closure(rec):
    rec["exclusions"] = sorted(rec["exclusions"] + [{"component": "retrieval-service",
                                                     "kind": "CATALOG_MODULE_WITH_SERVICE", "sources": ["ROADMAP"],
                                                     "reason": "test"}], key=lambda row: row["component"])


def _drop_exclusion(name):
    def mutate(rec):
        rec["exclusions"] = [row for row in rec["exclusions"] if row["component"] != name]
    return mutate


def _drop_fact(rec):
    rec["tenantFacts"].pop()


def _swap_facts(rec):
    rec["tenantFacts"][0], rec["tenantFacts"][1] = rec["tenantFacts"][1], rec["tenantFacts"][0]


def _bound_as_module_health(row):
    row["readiness"] = {"source": "MODULE_HEALTH"}
    row["exitEvidence"]["obligation"] = "MODULE_HEALTH"


CASES = [
    # V0 RP_SHAPE
    ("extra member", "RP_SHAPE", _set(["extra"], 1)),
    ("missing hKey", "RP_SHAPE", _edit_row(RETRIEVAL, lambda row: row.pop("hKey"))),
    ("state member in a module row", "RP_SHAPE", _edit_row(RETRIEVAL, lambda row: row.update(state="DONE"))),
    ("NOT_RUN member", "RP_SHAPE", _edit_row(RETRIEVAL, lambda row: row["exitEvidence"].update(NOT_RUN=True))),
    ("version floor on the tenant platform row", "RP_SHAPE", _edit_row(TENANT, lambda row: row.update(versionFloor="1"))),
    ("implementation on the tenant platform row", "RP_SHAPE",
     _edit_row(TENANT, lambda row: row.update(implementation={"packetId": "OP-001", "deliverableIndex": None}))),
    ("empty free-text reason", "RP_SHAPE", _edit_exclusion("valkey", lambda row: row.update(reason=""))),
    # V1 RP_CLOSURE
    ("dropped node", "RP_CLOSURE", _drop_node),
    ("added excluded module", "RP_CLOSURE", _add_excluded),
    ("white-goods profile id", "RP_CLOSURE", _set(["profile", "id"], "profile.white-goods-readonly-amd64")),
    ("dropped module row", "RP_CLOSURE", _drop_module_row),
    ("extra module row", "RP_CLOSURE", _extra_module_row),
    ("exact duplicate module row", "RP_CLOSURE", _duplicate_module_row),
    ("SELECTED/CLOSURE swap", "RP_CLOSURE", _edit_row(RETRIEVAL, _swap_class)),
    # V8 RP_PACK_BINDING
    ("pack row naming IND-BANK-005", "RP_PACK_BINDING",
     _edit_row(PACK, lambda row: row["implementation"].update(packetId="IND-BANK-005"))),
    ("inReleaseSet true", "RP_PACK_BINDING", _set(["nonClaims", "industryPack", "inReleaseSet"], True)),
    ("changed releaseSetEntry", "RP_PACK_BINDING", _set(["nonClaims", "industryPack", "releaseSetEntry"], "changed")),
    ("successor IND-BANK-004", "RP_PACK_BINDING", _set(["nonClaims", "industryPack", "successor"], "IND-BANK-004")),
    ("effectiveBinding IND-BANK-005", "RP_PACK_BINDING",
     _set(["nonClaims", "industryPack", "effectiveBinding"], "IND-BANK-005")),
    # V2 RP_OWNER_PACKET
    ("blank packet", "RP_OWNER_PACKET", _edit_row(RETRIEVAL, lambda row: row["implementation"].update(packetId=""))),
    ("unpublished packet id IND-BANK-005", "RP_OWNER_PACKET",
     _edit_row(RETRIEVAL, lambda row: row["implementation"].update(packetId="IND-BANK-005"))),
    ("same-repository packet swap", "RP_OWNER_PACKET",
     _edit_row(RETRIEVAL, lambda row: row["implementation"].update(packetId="KN-DOM-001"))),
    ("changed deployable artifact", "RP_OWNER_PACKET",
     _edit_row(RETRIEVAL, lambda row: row["deployables"][0].update(artifact="other/retrieval-service"))),
    ("REPOSITORY_PACKET module relabelled TENANT_PLATFORM", "RP_OWNER_PACKET", _edit_row(POLICY, _relabel)),
    ("attestationRef external.postgresql", "RP_OWNER_PACKET",
     _edit_row(TENANT, lambda row: row.update(attestationRef="external.postgresql"))),
    ("attestationRef on a REPOSITORY row", "RP_OWNER_PACKET", _edit_row(CONTRACTS, _attestation_on_repository)),
    ("tenant row with a changed owner", "RP_OWNER_PACKET",
     _edit_row(TENANT, lambda row: row["owner"].update(name="another distribution"))),
    ("tenant row with a changed deployable artifact", "RP_OWNER_PACKET",
     _edit_row(TENANT, lambda row: row["deployables"][0].update(artifact="other-kubernetes-api"))),
    ("tenant row with a changed kind", "RP_OWNER_PACKET", _edit_row(TENANT, lambda row: row.update(kind="ADAPTER"))),
    ("retrieval-service hKey H7 to H9", "RP_OWNER_PACKET", _edit_row(RETRIEVAL, lambda row: row.update(hKey="H9"))),
    ("kubernetes-upstream hKey to null", "RP_OWNER_PACKET", _edit_row(TENANT, lambda row: row.update(hKey=None))),
    ("tampered operator row", "RP_OWNER_PACKET",
     _edit_row(OPERATOR, lambda row: row["owner"].update(name="mas-harness-trust-plane"))),
    # V3 RP_EXIT
    ("removed binding", "RP_EXIT", _edit_row(RETRIEVAL, lambda row: row["readiness"].update(serviceId="index-worker"))),
    ("bound module recorded as MODULE_HEALTH", "RP_EXIT", _edit_row(OPERATOR, _bound_as_module_health)),
    ("wrong criteria count", "RP_EXIT", _edit_row(OPERATOR, lambda row: row["readiness"].update(criteriaCount=3))),
    ("another evidence record", "RP_EXIT",
     _edit_row(RETRIEVAL, lambda row: row["exitEvidence"].update(evidenceRecord="CONF-A2-001"))),
    ("at changed", "RP_EXIT", _edit_row(RETRIEVAL, lambda row: row["exitEvidence"].update(at="CONF-A3-001"))),
    ("grounding evaluation dropped from a cited row", "RP_EXIT",
     _edit_row(RETRIEVAL, lambda row: row["exitEvidence"].update(evidenceKinds=["QUALIFICATION_EVIDENCE"]))),
    ("grounding evaluation added to a non-cited row", "RP_EXIT",
     _edit_row(CONTRACTS, lambda row: row["exitEvidence"].update(
         evidenceKinds=["QUALIFICATION_EVIDENCE", "GROUNDING_EVALUATION"]))),
    # V4 RP_PROVIDER_SET
    ("H10 moved to deferred", "RP_PROVIDER_SET", _h10_to_deferred),
    ("wrong harness id for a key", "RP_PROVIDER_SET",
     lambda rec: rec["providerSet"]["in"][0].update(harness="runtime.model-inference")),
    ("dropped platformNonHarness entry", "RP_PROVIDER_SET", _drop_platform("platform.sdk")),
    ("platform.external-prerequisite removed", "RP_PROVIDER_SET", _drop_platform("platform.external-prerequisite")),
    # V5 RP_EXCLUSION
    ("an excluded module in the closure", "RP_EXCLUSION", _excluded_in_closure),
    ("dropped profile exclusion", "RP_EXCLUSION", _drop_exclusion("vllm")),
    ("NOT_IN_CATALOG row without its decision", "RP_EXCLUSION",
     _edit_exclusion("valkey", lambda row: row.pop("roadmapDecision"))),
    ("wrong kind (ollama with a service)", "RP_EXCLUSION",
     _edit_exclusion("ollama", lambda row: row.update(kind="CATALOG_MODULE_WITH_SERVICE"))),
    ("wrong source", "RP_EXCLUSION", _edit_exclusion("tool-broker", lambda row: row.update(sources=["ROADMAP"]))),
    # V6 RP_CATALOG_BYTES (the record part; the byte parts are below)
    ("digest of another era", "RP_CATALOG_BYTES", _set(["profile", "overlaySha256"], "0" * 64)),
    # V7 RP_TENANT_FACTS
    ("ten-row set", "RP_TENANT_FACTS", _drop_fact),
    ("unsorted pair", "RP_TENANT_FACTS", _swap_facts),
    ("fifth namedInRoadmap", "RP_TENANT_FACTS", _edit_fact("external.kubernetes-api",
                                                           lambda fact: fact.update(namedInRoadmap=True))),
    ("wrong supplier", "RP_TENANT_FACTS", _edit_fact("external.postgresql",
                                                     lambda fact: fact["supplier"].update(name="someone else"))),
    ("status other than the catalog's", "RP_TENANT_FACTS",
     _edit_fact("external.postgresql", lambda fact: fact["attestation"].update(installUnitDigestStatus="PINNED"))),
    ("requirement NONE", "RP_TENANT_FACTS",
     _edit_fact("external.postgresql", lambda fact: fact["attestation"].update(requirement="NONE"))),
    ("non-null envelope digest", "RP_TENANT_FACTS",
     _edit_fact("external.postgresql", lambda fact: fact["attestation"]["envelope"].update(digest="sha256:" + "a" * 64))),
]


@pytest.mark.parametrize("name,code,mutate", CASES, ids=[case[0] for case in CASES])
def test_each_record_fault_fails_for_its_code(name, code, mutate):
    rec = _record()
    mutate(rec)
    with pytest.raises(ValueError, match=r"^%s: " % code):
        rp.check(_reader(rec), _packets())


def test_an_unpublished_catalog_packet_fails_for_owner_packet():
    with pytest.raises(ValueError, match=r"^RP_OWNER_PACKET: packet KN-RET-001 is published"):
        rp.check(_reader(), _packets() - {"KN-RET-001"})


def test_a_packet_yaml_naming_another_repository_fails_for_owner_packet():
    path = "task-packets/KN-RET-001.yaml"
    raw = (ROOT / path).read_bytes().replace(b"repository: mas-harness-knowledge-plane",
                                             b"repository: mas-harness-trust-plane", 1)
    assert raw != (ROOT / path).read_bytes()
    with pytest.raises(ValueError, match=r"^RP_OWNER_PACKET: packet KN-RET-001 names the owner"):
        rp.check(_reader(files={path: raw}), _packets())


def test_a_tampered_operator_row_never_reaches_an_operator_packet_read():
    rec = _record()
    _row(rec, OPERATOR)["owner"]["name"] = "mas-harness-trust-plane"
    with pytest.raises(ValueError, match=r"^RP_OWNER_PACKET: owner of " + OPERATOR):
        rp.check(_reader(rec), _packets())


def test_one_changed_catalog_byte_fails_for_catalog_bytes():
    raw = bytearray((ROOT / rp.PROVIDERS_PATH).read_bytes())
    raw[0] ^= 1
    with pytest.raises(ValueError, match=r"^RP_CATALOG_BYTES: base bytes of "):
        rp.check(_reader(files={rp.PROVIDERS_PATH: bytes(raw)}), _packets())


def test_a_changed_hkey_map_fails_for_catalog_bytes():
    raw = (ROOT / rp.HKEY_MAP_PATH).read_bytes() + b"\n"
    with pytest.raises(ValueError, match=r"^RP_CATALOG_BYTES: H-key map"):
        rp.check(_reader(files={rp.HKEY_MAP_PATH: raw}), _packets())


REGISTRY_FAULTS = [
    ("a second rider", _registry(lambda briefs, template: briefs.append(dict(template, series=rp.RIDER_SERIES)))),
    ("no rider", _registry(lambda briefs, template: briefs.pop())),
    ("a re-serialised registry", _registry(serialize=lambda r: (json.dumps(r, separators=(",", ":")) + "\n").encode())),
    ("the rider in a wrong position", _registry(lambda briefs, template: briefs.insert(0, briefs.pop()))),
    ("another packet's rider appended", _registry(lambda briefs, template: briefs.append(
        dict(template, series="MET-ADOPT-007/packet")))),
    # RP-C2-1: the same content with the rider's members in another order.
    ("the rider's members permuted", _registry(lambda briefs, template: briefs.append(
        dict(reversed(list(briefs.pop().items())))))),
]


@pytest.mark.parametrize("name,raw", REGISTRY_FAULTS, ids=[case[0] for case in REGISTRY_FAULTS])
def test_each_registry_fault_fails_for_registry(name, raw):
    with pytest.raises(ValueError, match=r"^RP_REGISTRY: "):
        rp.check(_reader(files={rp.BRIEFS_PATH: raw}), _packets())


# RP-C2-2: bytes that are not UTF-8 JSON refuse with the reading check's code, never an uncoded error.
ENCODING_CASES = [
    ("record: invalid UTF-8", rp.RECORD_PATH, b"\xff\xfe", "RP_SHAPE"),
    ("record: a UTF-8 byte-order mark", rp.RECORD_PATH, b"\xef\xbb\xbf" + (ROOT / rp.RECORD_PATH).read_bytes(), "RP_SHAPE"),
    ("record: not JSON", rp.RECORD_PATH, b"not json\n", "RP_SHAPE"),
    ("registry: invalid UTF-8", rp.BRIEFS_PATH, b"\xff\xfe", "RP_REGISTRY"),
    ("registry: a UTF-8 byte-order mark", rp.BRIEFS_PATH, b"\xef\xbb\xbf" + _registry(), "RP_REGISTRY"),
    ("registry: not JSON", rp.BRIEFS_PATH, b"not json\n", "RP_REGISTRY"),
    # RP-C3-1: text nested beyond the decoder's recursion depth.
    ("record: nested beyond the decoder's depth", rp.RECORD_PATH, b"[" * 200000, "RP_SHAPE"),
    ("registry: nested beyond the decoder's depth", rp.BRIEFS_PATH, b"[" * 200000, "RP_REGISTRY"),
]


@pytest.mark.parametrize("name,path,raw,code", ENCODING_CASES, ids=[case[0] for case in ENCODING_CASES])
def test_bytes_that_are_not_utf8_json_fail_for_the_reading_checks_code(name, path, raw, code):
    with pytest.raises(ValueError, match=r"^%s: not UTF-8 JSON$" % code):
        rp.check(_reader(files={path: raw}), _packets())


# RP-C3-3: valid JSON holding an integer beyond Python's integer-conversion limit refuses with the reading check's code.
@pytest.mark.parametrize("path,code", [(rp.RECORD_PATH, "RP_SHAPE"), (rp.BRIEFS_PATH, "RP_REGISTRY")])
def test_a_json_integer_beyond_the_conversion_limit_fails_for_the_reading_checks_code(path, code):
    raw = b'{"a": ' + b"1" * 5000 + b"}\n"
    with pytest.raises(ValueError, match=r"^%s: JSON integer beyond the conversion limit$" % code):
        rp.check(_reader(files={path: raw}), _packets())


def test_a_non_operator_packet_yaml_that_is_not_utf8_fails_for_owner_packet():
    with pytest.raises(ValueError, match=r"^RP_OWNER_PACKET: packet KN-RET-001 is not UTF-8$"):
        rp.check(_reader(files={"task-packets/KN-RET-001.yaml": b"\xff\xfe"}), _packets())


def test_an_unparseable_published_successor_packet_fails_for_catalog_bytes():
    # RP-C3-2: a published SECTOR-D1 successor (neither the blocker IND-BANK-005 nor the notice proposal) whose packet
    # YAML, read through this reader, does not parse.
    files = {"task-packets/IND-BANK-001.yaml": b"a: [\n"}
    with pytest.raises(ValueError, match=r"^RP_CATALOG_BYTES: the overlay era does not check: "):
        rp.check(_reader(files=files), _packets() | {"IND-BANK-001"})


# Q-RP-PROJ (a1), design E2: the catalogs reach the model only through the injected reader and packet set. The c2
# model read them from the disk: it passed the R11 case below, and refused the IND-BANK-005 case with RP_PACK_BINDING
# (the record's successor is unpublished), where c3 refuses it with RP_CATALOG_BYTES (RP-C3-6).
R11_PLAN = "docs/repositories/11-mas-harness-distribution.md"


def test_a_changed_r11_notice_through_the_reader_fails_for_catalog_bytes():
    raw = (ROOT / R11_PLAN).read_bytes()
    line = b"7. `DIST-004-helm-profiles`:"
    assert raw.count(b"\n" + line) == 1
    changed = raw.replace(b"\n" + line, b"\n" + line.replace(b"`:", b"` :"), 1)
    with pytest.raises(ValueError, match=r"^RP_CATALOG_BYTES: the overlay era does not check: the DIST-004 list item"):
        rp.check(_reader(files={R11_PLAN: changed}), _packets())


def test_the_injected_packet_set_decides_the_overlay_era():
    with pytest.raises(ValueError, match=r"^RP_CATALOG_BYTES: the overlay era does not check: IND-BANK-005 is published"):
        rp.check(_reader(), _packets() | {"IND-BANK-005"})


def test_the_yaml_catalogs_parse_as_effective_catalog_parses_them():
    for path in (rp.PROVIDERS_PATH, rp.SERVICES_PATH):
        assert safe_load(sector_catalog.effective_bytes(path)) == sector_catalog.effective_catalog(path)


# RP-C4-1..3 (c5): any other exception of the era check, of V9's serialization and of provider-adoption's use refuses
# with the check's code and names the original exception type.
SUCCESSOR = "task-packets/IND-BANK-001.yaml"
SUCCESSOR_ID = "IND-BANK-001"


def _nested_flow_mappings(depth):
    return b"a: " + b"{a: " * depth + b"b" + b"}" * depth + b"\n"


def _nested_block_mappings(depth):
    return b"".join(b"  " * level + b"a:\n" for level in range(depth)) + b"  " * depth + b"b\n"


NESTED_SUCCESSORS = [("flow mappings 500 deep", _nested_flow_mappings(500)),
                     ("flow mappings 600 deep", _nested_flow_mappings(600)),
                     ("block mappings 500 deep", _nested_block_mappings(500)),
                     ("block mappings 600 deep", _nested_block_mappings(600))]
UNHASHABLE_SUCCESSORS = [("block", b"? [a]\n: b\n"), ("flow", b"{[a]: b}\n")]


@pytest.mark.parametrize("name,raw", NESTED_SUCCESSORS, ids=[case[0] for case in NESTED_SUCCESSORS])
def test_a_published_successor_nesting_mappings_past_the_recursion_limit_fails_for_catalog_bytes(name, raw):
    with pytest.raises(ValueError, match=r"^RP_CATALOG_BYTES: the overlay era does not check: RecursionError: "):
        rp.check(_reader(files={SUCCESSOR: raw}), _packets() | {SUCCESSOR_ID})


@pytest.mark.parametrize("name,raw", UNHASHABLE_SUCCESSORS, ids=[case[0] for case in UNHASHABLE_SUCCESSORS])
def test_a_published_successor_with_an_unhashable_mapping_key_fails_for_catalog_bytes(name, raw):
    with pytest.raises(ValueError, match=r"^RP_CATALOG_BYTES: the overlay era does not check: TypeError: "):
        rp.check(_reader(files={SUCCESSOR: raw}), _packets() | {SUCCESSOR_ID})


def _overlay_changed_after_the_pinned_read():
    """A reader that serves the overlay's pinned bytes on the model's own read and 200000 '[' on the later reads."""
    base, reads = _reader(), []

    def read(path):
        if path == rp.OVERLAY_PATH:
            reads.append(path)
            if len(reads) > 1:
                return b"[" * 200000
        return base(path)
    return read


def test_an_overlay_changed_after_the_models_pinned_read_fails_for_catalog_bytes():
    with pytest.raises(ValueError, match=r"^RP_CATALOG_BYTES: the overlay era does not check: RecursionError: "):
        rp.check(_overlay_changed_after_the_pinned_read(), _packets())


def _registry_with_a_member_nested(depth):
    raw = _registry()
    end = raw.rindex(b"}")
    return raw[:end].rstrip() + b',\n "x": ' + b"[" * depth + b"]" * depth + b"\n}\n"


def test_a_registry_nested_past_the_recursion_limit_within_the_decoders_depth_fails_for_registry():
    # RP-C4-2: valid JSON the decoder reads, nested past the interpreter's recursion limit for V9's serialization.
    with pytest.raises(ValueError, match=r"^RP_REGISTRY: the registry does not serialize: RecursionError: "):
        rp.check(_reader(files={rp.BRIEFS_PATH: _registry_with_a_member_nested(5000)}), _packets())


ADOPTION_SHAPES = [("an empty object", b"{}\n", "KeyError"), ("a list", b"[]\n", "TypeError"),
                   ("an integer row", b'{"harnessCoverage": [1]}\n', "TypeError"),
                   ("a list harnessId", b'{"harnessCoverage": [{"harnessId": ["x"]}]}\n', "TypeError")]


@pytest.mark.parametrize("name,raw,kind", ADOPTION_SHAPES, ids=[case[0] for case in ADOPTION_SHAPES])
def test_provider_adoption_of_a_shape_the_read_raises_on_fails_for_provider_set(name, raw, kind):
    # RP-C4-3: provider-adoption is valid JSON of a shape V4's read raises on (not every other shape; RP-C5-2).
    with pytest.raises(ValueError, match=r"^RP_PROVIDER_SET: provider-adoption is not of the read shape: %s: " % kind):
        rp.check(_reader(files={rp.ADOPTION_PATH: raw}), _packets())


CODES = ("RP_SHAPE", "RP_CLOSURE", "RP_OWNER_PACKET", "RP_EXIT", "RP_PROVIDER_SET", "RP_EXCLUSION", "RP_CATALOG_BYTES",
         "RP_TENANT_FACTS", "RP_PACK_BINDING", "RP_REGISTRY")
PROBE_FORMS = (("invalid UTF-8", b"\xff\xfe\x00"), ("nested [", b"[" * 200000), ("nested YAML", b"a: " + b"[" * 100000),
               ("5000-digit integer", b'{"a": ' + b"1" * 5000 + b"}"), ("open flow sequence", b"a: ["), ("empty", b""))
# The YAML loader under the era check exits by SIGSEGV on the two deeply nested forms in a published successor's
# packet YAML (RP-C4-4, recorded, not codeable in-process), so the successor runs only the other four.
SUCCESSOR_FORMS = ("invalid UTF-8", "5000-digit integer", "open flow sequence", "empty")


@pytest.fixture(scope="module")
def probe_cases():
    """The class probe, generated deterministically: every path check() reads on the real record, sorted, with each
    malformed form (172 cases with the published successor's four), then c5's new cases. Each case is (label, a reader
    factory, the packet set)."""
    log = []
    rp.check(_reader(log=log), _packets())
    forms = dict(PROBE_FORMS)
    files_case = lambda files: (lambda: _reader(files=files))
    cases = [("%s / %s" % (path, name), files_case({path: raw}), _packets())
             for path in sorted(set(log)) for name, raw in PROBE_FORMS]
    cases += [("%s / %s" % (SUCCESSOR, name), files_case({SUCCESSOR: forms[name]}), _packets() | {SUCCESSOR_ID})
              for name in SUCCESSOR_FORMS]
    assert len(cases) == 172
    cases += [("%s / %s" % (SUCCESSOR, name), files_case({SUCCESSOR: raw}), _packets() | {SUCCESSOR_ID})
              for name, raw in NESTED_SUCCESSORS + UNHASHABLE_SUCCESSORS]
    cases += [("overlay changed after the pinned read", _overlay_changed_after_the_pinned_read, _packets()),
              ("registry nested 5000 deep", files_case({rp.BRIEFS_PATH: _registry_with_a_member_nested(5000)}),
               _packets())]
    cases += [("provider-adoption / " + name, files_case({rp.ADOPTION_PATH: raw}), _packets())
              for name, raw, _ in ADOPTION_SHAPES]
    return cases


def test_no_uncoded_exception_escapes_check_over_the_class_probe(probe_cases):
    escaped = []
    for label, make_reader, packets in probe_cases:
        try:
            rp.check(make_reader(), packets)
            escaped.append((label, "accepted"))
        except ValueError as error:
            if str(error).split(":", 1)[0] not in CODES:
                escaped.append((label, "uncoded ValueError"))
        except Exception as error:
            escaped.append((label, type(error).__name__))
    assert len(probe_cases) == 172 + 12 and escaped == []


TYPE_CASES = [
    # RP-C1-1: bool, int and float are distinct.
    ("criteriaCount true on a 1-criterion row",
     _edit_row(RETRIEVAL, lambda row: row["readiness"].update(criteriaCount=True))),
    ("criteriaCount 2.0 on a 2-criterion row", _edit_row(OPERATOR, lambda row: row["readiness"].update(criteriaCount=2.0))),
    ("successorPublished 0", _set(["nonClaims", "industryPack", "successorPublished"], 0)),
    ("inReleaseSet 0", _set(["nonClaims", "industryPack", "inReleaseSet"], 0)),
    # RP-C1-2: identifier members are type-checked before any use.
    ("integer module-row id", _edit_row(RETRIEVAL, lambda row: row.update(id=7))),
    ("integer tenant-fact id", _edit_fact("external.postgresql", lambda fact: fact.update(id=7))),
    ("integer exclusion component", _edit_exclusion("valkey", lambda row: row.update(component=7))),
    ("integer providerSet.in", _set(["providerSet", "in"], 7)),
    ("integer providerSet.in key", lambda rec: rec["providerSet"]["in"][0].update(key=1)),
    ("integer owner name", _edit_row(TENANT, lambda row: row["owner"].update(name=7))),
]


@pytest.mark.parametrize("name,mutate", TYPE_CASES, ids=[case[0] for case in TYPE_CASES])
def test_each_type_fault_fails_for_shape_without_a_type_error(name, mutate):
    rec = _record()
    mutate(rec)
    with pytest.raises(ValueError, match=r"^RP_SHAPE: "):
        rp.check(_reader(rec), _packets())


def test_an_emptied_operator_set_is_stopped_by_the_module_guard_before_any_read(monkeypatch):
    log = []
    monkeypatch.setattr(rp, "operator_rows", lambda ownership, internal: frozenset())
    with pytest.raises(ValueError, match=r"^RP_OWNER_PACKET: an operator packet YAML is never opened"):
        rp.check(_reader(log=log), _packets())
    assert not any(path.startswith(FIXTURE_OPERATOR_PATH) for path in log)


def test_with_the_module_guard_bypassed_the_readers_guard_fires(monkeypatch):
    monkeypatch.setattr(rp, "OPERATOR_PREFIX", "\x00")
    with pytest.raises(OperatorRead, match=r"^task-packets/OP-"):
        rp.check(_reader(), _packets())
