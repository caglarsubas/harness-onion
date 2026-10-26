"""Exact source lineage for MET-ENFORCE-042; the I01 digest contract v2 (S1, with W1 and edge record v11), adopted as candidate c4 after its in-tree CONTRACT rounds 1 to 3, with its D5a oracle, B-L1-4's pins record and the registry rider: the head keeps the full fan-in (8 own and 76 predecessor routes, every catalog walk and round trip, the full payload loop), and the semantic check (the freeze, the files added, the adoption with its three rounds and the oracle identity, the model replaying its vectors from this era's bytes, admission v4's sealed rendering, B-I01S-1's binding, edge record v11, the pins and classes, the registry's two series, the derived gate check and the canonical hunks) has a failing case for every refusal, each on plain data. W1 follows: VPO's validate_messages and profile v2's validate and precondition on the complete I01 positive, with no skip, expected-failure mark or import guard."""
import ast
import json
from copy import deepcopy
import os
import re
import stat
from pathlib import Path
from types import MappingProxyType

import pytest

from scripts import validate_policy_observation_digests_v2 as profile
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
    # The newer MET-LINUX-008 layer is projected away before this layer's payload checks.
    return profile.successor.historical_catalog(packets())


def changed_test():
    return next(path for path in profile._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert profile.validate() is None
    current = packets()
    accepted = profile.historical_catalog(current)
    assert len(current) == 267 and len(accepted) == 264
    assert set(accepted) == set(current) - {profile.NEW_PACKET, profile.successor.NEW_PACKET,
                                            profile.successor.successor.NEW_PACKET}
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


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "ml9_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = profile.historical_bytes(path, raw) if route in ("current_test", "old_bytes") else None
    current_packets = packets() if route == "catalog" else None
    layer = layer_packets() if route == "payloads" else None
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
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
    with pytest.raises(ValueError, match="policy observation digests v2 history authority digest"):
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
    assert len(profile.historical_catalog(current)) == 264


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
    assert len(profile.historical_catalog(current)) == 264
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
    assert len(rules) == 265 and len(parsed) == 264
    assert profile._packet_rules() is rules and len(parsed) == 264
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
    with pytest.raises(ValueError, match="policy observation digests v2 history authority digest"):
        profile.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = layer_packets()
    profile.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "policy-observation-digests-v2-authority.json").write_bytes(
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
    # The newer MET-LINUX-008 layer refuses a mutated validator before this layer.
    with pytest.raises(ValueError, match="unreviewed current source: scripts/validate_policy_observation_digests_v2.py"):
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
            assert all("validate_" not in alias.name or alias.name == "validate_met_linux_008"
                       for alias in node.names)


def _count_authority_reads(monkeypatch):
    counts = {}
    for module in (profile.successor, profile, ml9, lpka, lpi, lkg, pks, rrv, pod, evs, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner):
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
    expected = {module.__name__: 1 for module in (profile.successor, profile, ml9, lpka, lpi, lkg, pks, rrv, pod, evs, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner)}
    if route == "current_test":
        # The forward route reads this layer's newest bytes and then projects them forward once more.
        assert all(counts[name] >= 1 for name in expected) and set(counts) == set(expected)
    else:
        assert counts == expected


# MET-ENFORCE-042 (the I01 digest contract v2, S1 with W1 and S2): this era's check, and a failing case for every check.
# Every mutant below is applied to plain data handed to the layer's pure checks: nothing in the layer or the library is
# patched or swapped. The mutants are built by the pure helpers _<area>_mutant(change), one change name per mutant. The
# v2 model, its frozen models and the evolution surface model are executed from this era's verified bytes through the
# layer's era loader. This test also reaches what the layer does not, since the names are not attribute names the frozen
# allow-list admits: the era model's SEALED_NAMESPACE and its admission and profile imports. W1 follows the check map.

VALIDATE = profile.validate_policy_observation_digests_v2
# Tamper values name paths that already exist and that this packet does not carry in the tampered place.
OTHER_PATH = "scripts/validate_met_linux_009.py"
_CACHE = {}


def _models():
    if "models" not in _CACHE:
        _CACHE["models"] = profile.era_models()
    return _CACHE["models"]


def _load(path):
    return json.loads(profile._verified(path))


def _rounds():
    return [(profile._verified(profile.REVIEW_RECORDS[n - 1]), profile._verified(profile.REVIEW_IDENTITIES[n - 1]))
            for n in profile.ROUNDS]


def _pins():
    return _load(profile.PINS_PATH)


def _changed():
    return profile._packet_paths()


def _changed_rules():
    if "rules" not in _CACHE:
        _CACHE["rules"] = profile.authority()["changedFiles"]
    return _CACHE["rules"]


def _gate():
    return _models()[7].check(_load(profile.SURFACE_RECORD))["gateMaterial"]


def _frozen_files():
    return {path: profile._verified(path)
            for path in profile.FROZEN_MODELS + profile.FROZEN_INPUTS + (profile.P2_SCHEMA,)}


def _replay_count():
    if "count" not in _CACHE:
        _CACHE["count"] = _models()[0].check_vectors(_load(profile.VECTORS_PATH), _frozen_files())
    return _CACHE["count"]


def _flip(text):
    """A different lowercase hex digest of the same length."""
    return text[:-1] + ("0" if text[-1] != "0" else "1")


def _encode(value):
    return (json.dumps(value, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def test_the_contract_holds_for_this_era():
    assert VALIDATE() is None


def test_the_era_holds_the_added_files_the_pins_the_registry_and_the_surface():
    pins = [row["path"] for row in _pins()["unchangedPins"] if row["rule"] == "BYTE_IDENTICAL"]
    assert set(profile.ERA_SHA256) == set(profile.NEW_FILES) | set(pins) | {
        profile.REGISTRY_PATH, profile.PACKET_BRIEF, profile.CONTRACT_BRIEF, profile.SURFACE_RECORD, profile.SURFACE_MODEL}
    assert len(profile.ERA_SHA256) == 272 and len(profile.NEW_FILES) == 17 and len(set(profile.NEW_FILES)) == 17
    assert len(pins) == 250 and not set(pins) & set(profile.NEW_FILES)
    assert set(profile.FROZEN_MODELS + profile.FROZEN_INPUTS) | {
        profile.P2_SCHEMA, profile.P2_VECTORS, profile.V4_README, profile.V4_VECTORS, profile.V4_SEALED, profile.V1_STATUS,
        profile.V1_VECTORS, profile.EDGE_V10} <= set(pins)
    assert profile.ERA_SHA256[profile.V4_SEALED] == profile.SEALED_SHA256
    # No chain validator and no chain test is in the era: the step-rule pins (PODL and PODT) are bound through the
    # authority's predecessor digests, and the era's only test is the D5a oracle (plus I01 v1's frozen oracle).
    assert not any(path.startswith("scripts/validate_") for path in profile.ERA_SHA256)
    assert {path for path in profile.ERA_SHA256 if path.startswith("tests/")} == {
        profile.ORACLE_TEST, "tests/test_policy_observation_digests_oracle.py"}
    for row in _pins()["unchangedPins"]:
        if row["rule"] == "BYTE_IDENTICAL":
            assert profile.ERA_SHA256[row["path"]] == row["sha256"]
    for path, expected in profile.ERA_SHA256.items():
        assert profile.digest(profile.reviewed_bytes(path)) == expected


@pytest.mark.parametrize("path", sorted(profile.ERA_SHA256))
def test_every_era_file_is_bound_by_digest(path):
    raw = profile._verified(path)
    assert profile._era_bytes(path, raw) == raw
    for changed in (raw + b" ", bytearray(raw)):
        with pytest.raises(ValueError, match=re.escape("unreviewed DIGEST-CONTRACT-V2 source: " + path)):
            profile._era_bytes(path, changed)


def test_a_path_outside_the_era_is_refused_before_it_is_read():
    for path in (profile.CONTRACT_DIR + "notes.md", profile.CONTRACT_DIR + "review-round4.json",
                 "architecture/policy-observation-digests/design/notes.md", "scripts/validate_proxy_contract.py",
                 "scripts/validate_policy_observation.py", "architecture/policy-observation-inputs/schema.json",
                 OTHER_PATH, profile.VALIDATOR_PATH, profile.HEAD_TEST, profile.PACKET_PATH, profile.AUTHORITY_PATH,
                 profile.LIVING_CATALOGS[0], "architecture/review-record/legacy-review-records.json", None):
        with pytest.raises(ValueError, match="MET-ENFORCE-042 reviewed bytes are bound: "):
            profile._verified(path)
        with pytest.raises(ValueError, match="MET-ENFORCE-042 reviewed bytes are bound: "):
            profile._era_bytes(path, b"")


ERA_MODELS_MESSAGE = "the model runs this era's frozen models: I06 v4 with I06 v1 and v3"


@pytest.mark.parametrize("change", ["short", "not_tuple", "swapped", "other_v1", "other_np4"])
def test_the_model_runs_this_eras_frozen_models(change):
    models = _models()
    profile.check_era_models(models)
    assert [model.__name__ for model in models] == [
        "_met_enforce_042_policy_observation_digests_v2", "_met_enforce_042_i06_backend_profile_v4",
        "_met_enforce_042_i06_backend_profile_v3", "_met_enforce_042_i06_backend_profile",
        "_met_enforce_042_native_qualification_v4", "_met_enforce_042_admission_semantics_v4",
        "_met_enforce_042_proxy_profile_v2", "_met_enforce_042_evolution_surface"]
    assert [model.__file__ for model in models] == [str(profile.ROOT / path) for path in (
        profile.MODEL_PATH, profile.I06V4_MODEL, profile.I06V3_MODEL, profile.I06V1_MODEL, profile.NQ4_MODEL,
        profile.V4_MODEL, profile.P2_MODEL, profile.SURFACE_MODEL)]
    # The era imports: the model's admission and profile modules are this era's admission v4 and profile v2.
    assert models[0].adm is models[5] and models[0].proxy_profile_v2 is models[6] and models[0].i06v1 is models[3]
    if change == "short":
        models = models[:5]
    elif change == "not_tuple":
        models = list(models)
    elif change == "swapped":
        models = (models[0], models[2], models[1]) + models[3:]
    elif change == "other_v1":
        models = models[:3] + (models[5],) + models[4:]
    else:
        models = models[:4] + (models[6],) + models[5:]
    with pytest.raises(ValueError, match=re.escape(ERA_MODELS_MESSAGE)):
        profile.check_era_models(models)


# The freeze and the files this packet adds -----------------------------------------------------------------------------

FREEZE = "this packet edits only chain validators, tests, the three living catalogs and the registry: "


@pytest.mark.parametrize("path", ["scripts/policy_observation_digests.py", "scripts/policy_observation_digests_v2.py",
                                  "scripts/admission_semantics_v4.py", "scripts/proxy_profile_v2.py",
                                  "scripts/evolution_surface.py", "scripts/review_record.py", "scripts/chain_identity.py",
                                  "architecture/policy-observation-digests/vectors.json",
                                  "architecture/policy-observation-digests/status.json",
                                  "architecture/policy-observation-digests-v2/README.md",
                                  "architecture/artifact-edges/operator-harness-engineering-v10.json",
                                  "architecture/review-record/legacy-review-records.json",
                                  "architecture/review-record/README.md",
                                  "architecture/evolution-surface/evolution-surface.json",
                                  "architecture/chain-compaction/identity-rule.json",
                                  "architecture/linux-probe-kit-admission/mechanics-pins.json",
                                  "architecture/proxy-contract-inputs/profile.schema.json",
                                  "docs/alpha-2/POLICY_OBSERVATION_READINESS.md", "docs/DEVELOPMENT_STATUS.md",
                                  "tests/conftest.py", "conftest.py", "scripts/validate_x/y.py", "scripts/validate_x.txt",
                                  "ci/linux-runner/common.py", "pyproject.toml", None])
def test_the_freeze_refuses_every_other_change(path):
    changed = list(profile._PROJECTION_RULES)
    profile.check_freeze(changed)
    assert profile.REGISTRY_PATH in changed
    with pytest.raises(ValueError, match=re.escape(FREEZE)):
        profile.check_freeze(changed + [path])


def _added_mutant(change):
    added = list(profile.NEW_FILES) + [profile.HEAD_TEST]
    if change == "missing":
        added.remove(profile.STATUS_PATH)
    elif change == "extra":
        added.append(profile.CONTRACT_DIR + "review-round4.json")
    elif change == "duplicate":
        added.append(profile.MODEL_PATH)
    elif change == "no_head_test":
        added.remove(profile.HEAD_TEST)
    elif change == "no_pins":
        added.remove(profile.PINS_PATH)
    elif change == "no_edge":
        added.remove(profile.EDGE_V11)
    else:
        added = tuple(added)
    return added


@pytest.mark.parametrize("change", ["missing", "extra", "duplicate", "no_head_test", "no_pins", "no_edge", "not_list"])
def test_the_packet_adds_exactly_its_files_each_once(change):
    profile.check_new_files(list(profile.NEW_FILES) + [profile.HEAD_TEST])
    profile.check_new_files(list(profile.authority()["newFiles"]))
    with pytest.raises(ValueError, match="this packet adds exactly its contract files, model, edge record, oracle test "
                                         "and layer test, each once"):
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


# The adoption: status.json, the rounds, the source index and the oracle identity --------------------------------------

STATUS_MESSAGE = ("adopted DIGEST-CONTRACT-V2 status: candidate c4 with rounds 1 to 3, the oracle and v1's record by "
                  "digest")
STATUS_CHANGES = ["schema", "packet", "candidate", "base", "series", "state", "reviewer", "evidence", "native",
                  "installed", "wire", "adoption_ruling", "adoption_commit", "record_digest", "identity_digest",
                  "verdict", "record_path", "round_dropped", "rounds_not_list", "oracle_path", "oracle_digest",
                  "oracle_tests", "predecessor_record", "predecessor_digest", "predecessor_packet", "extra_key",
                  "missing_key", "key_order", "rounds_bytes", "oracle_bytes", "predecessor_bytes", "not_dict"]


def _status_mutant(change):
    status, rounds = _load(profile.STATUS_PATH), _rounds()
    oracle, predecessor = profile._verified(profile.ORACLE_IDENTITY), profile._verified(profile.V1_STATUS)
    rows = status["reviewRounds"]
    if change == "schema":
        status["schemaVersion"] = status["schemaVersion"].replace("/v1", "/v2")
    elif change == "packet":
        status["packet"] = "MET-ENFORCE-041"
    elif change == "candidate":
        status["candidate"] = "c3"
    elif change == "base":
        status["base"] = profile.BASE_COMMIT
    elif change == "series":
        status["reviewSeries"] = "MET-ENFORCE-042/packet"
    elif change == "state":
        status["contractState"] = "CONTRACT_CANDIDATE"
    elif change == "reviewer":
        status["independentReviewer"] = "the author"
    elif change == "evidence":
        status["evidenceClass"] = "NATIVE_ACCEPTANCE"
    elif change == "native":
        status["nativeAcceptance"] = True
    elif change == "installed":
        status["installed"] = True
    elif change == "wire":
        status["wireContract"] = 0
    elif change == "adoption_ruling":
        status["adoption"]["ruling"] = "MON-I01S-C3-ADOPT"
    elif change == "adoption_commit":
        status["adoption"]["candidateCommit"] = status["adoption"]["rebasedCommit"]
    elif change == "record_digest":
        rows[0]["recordSha256"] = _flip(rows[0]["recordSha256"])
    elif change == "identity_digest":
        rows[2]["identitySha256"] = _flip(rows[2]["identitySha256"])
    elif change == "verdict":
        rows[1]["verdict"] = "PASS_FOR_ADOPTION"
    elif change == "record_path":
        rows[1]["record"] = profile.REVIEW_RECORDS[0]
    elif change == "round_dropped":
        rows.pop()
    elif change == "rounds_not_list":
        rounds = tuple(rounds)
    elif change == "oracle_path":
        status["oracle"]["identity"] = profile.CONTRACT_DIR + "oracle-identity.json"
    elif change == "oracle_digest":
        status["oracle"]["identitySha256"] = _flip(status["oracle"]["identitySha256"])
    elif change == "oracle_tests":
        status["oracle"]["tests"] = profile.HEAD_TEST
    elif change == "predecessor_record":
        status["predecessorRecord"]["record"] = "architecture/policy-observation-digests/README.md"
    elif change == "predecessor_digest":
        status["predecessorRecord"]["sha256"] = _flip(status["predecessorRecord"]["sha256"])
    elif change == "predecessor_packet":
        status["predecessorRecord"]["packet"] = "MET-ENFORCE-040"
    elif change == "extra_key":
        status["merged"] = True
    elif change == "missing_key":
        del status["nonClaims"]
    elif change == "key_order":
        status = dict(reversed(list(status.items())))
    elif change == "rounds_bytes":
        rounds[1] = (rounds[1][0] + b" ", rounds[1][1])
    elif change == "oracle_bytes":
        oracle = oracle + b" "
    elif change == "predecessor_bytes":
        predecessor = predecessor + b" "
    else:
        status = list(status.items())
    return status, rounds, oracle, predecessor


@pytest.mark.parametrize("change", STATUS_CHANGES)
def test_the_status_is_closed_and_records_the_adoption(change):
    profile.check_status(_load(profile.STATUS_PATH), _rounds(), profile._verified(profile.ORACLE_IDENTITY),
                         profile._verified(profile.V1_STATUS))
    with pytest.raises(ValueError, match=re.escape(STATUS_MESSAGE)):
        profile.check_status(*_status_mutant(change))


def test_the_status_names_the_rounds_the_adoption_and_the_oracle():
    status = _load(profile.STATUS_PATH)
    assert [{key: row[key] for key in profile.ROUND_ROW_KEYS} for row in status["reviewRounds"]] == profile._round_rows(
        _rounds())
    assert status["adoption"] == dict(profile.ADOPTION)
    assert profile.ADOPTION["ruling"] == "MON-I01S-C4-ADOPT" and profile.ADOPTION["candidate"] == "c4"
    assert profile.ADOPTION["rebasedOnto"] == profile.BASE_COMMIT
    assert [row["recordSha256"][:8] for row in status["reviewRounds"]] == ["b25518c9", "5851a7c5", "d0815a65"]
    assert [row["identitySha256"][:8] for row in status["reviewRounds"]] == ["67e109dc", "58629e2e", "4da01b3d"]
    assert status["oracle"]["identitySha256"][:8] == "8be40cf6"
    assert status["predecessorRecord"]["sha256"][:8] == "4b20c7c1"


ROUND_CHANGES = ["schema", "kind", "series", "round", "round_text", "verdict", "subject", "base", "brief", "identity_schema",
                 "identity_path", "identity_digest", "identity_brief", "identity_subject", "identity_base",
                 "record_bytes", "brief_bytes", "not_bytes", "number"]


def _round_mutant(n, change):
    record_raw, identity_raw = _rounds()[n - 1]
    brief = profile._verified(profile.CONTRACT_BRIEF)
    record, identity = json.loads(record_raw), json.loads(identity_raw)
    if change == "schema":
        record["schemaVersion"] = "planeon.review-record/v1"
    elif change == "kind":
        record["kind"] = "PACKET"
    elif change == "series":
        record["series"] = "MET-ENFORCE-042/packet"
    elif change == "round":
        record["round"] = n % 3 + 1
    elif change == "round_text":
        record["round"] = str(n)
    elif change == "verdict":
        record["verdict"] = "PASS_FOR_ADOPTION" if n < 3 else "CHANGES_REQUIRED"
    elif change == "subject":
        record["subject"]["commit"] = profile.BASE_COMMIT
    elif change == "brief":
        record["briefSha256"] = _flip(record["briefSha256"])
    elif change == "identity_schema":
        identity["schemaVersion"] = "planeon.review-identity/v1"
    elif change == "identity_path":
        identity["record"]["path"] = profile.REVIEW_RECORDS[n % 3]
    elif change == "identity_digest":
        identity["record"]["sha256"] = _flip(identity["record"]["sha256"])
    elif change == "identity_brief":
        identity["briefSha256"] = _flip(identity["briefSha256"])
    elif change == "identity_subject":
        identity["subject"]["tree"] = _flip(identity["subject"]["tree"])
    elif change == "identity_base":
        identity["base"] = dict(identity["subject"], commit=profile.BASE_COMMIT)
    elif change == "base":
        record["base"] = dict(record["subject"], commit=profile.BASE_COMMIT)
        identity["base"] = record["base"]
    elif change == "record_bytes":
        return n, record_raw + b" ", identity_raw, brief
    elif change == "brief_bytes":
        return n, record_raw, identity_raw, brief + b" "
    elif change == "not_bytes":
        return n, record_raw.decode("utf-8"), identity_raw, brief
    elif change == "number":
        return 4, record_raw, identity_raw, brief
    if change.startswith("identity_"):
        return n, record_raw, _encode(identity), brief
    record_out = _encode(record)
    identity["record"]["sha256"] = profile.digest(record_out)
    return n, record_out, _encode(identity), brief


@pytest.mark.parametrize("change", ROUND_CHANGES)
@pytest.mark.parametrize("n", [1, 2, 3])
def test_each_contract_round_is_bound_to_its_record_and_identity(n, change):
    record_raw, identity_raw = _rounds()[n - 1]
    brief = profile._verified(profile.CONTRACT_BRIEF)
    profile.check_round(n, record_raw, identity_raw, brief)
    # The re-encoding the mutants use keeps a valid pair valid.
    record_out = _encode(json.loads(record_raw))
    identity = json.loads(identity_raw)
    identity["record"]["sha256"] = profile.digest(record_out)
    profile.check_round(n, record_out, _encode(identity), brief)
    with pytest.raises(ValueError, match="a CONTRACT round is bound to its published record and identity: round "):
        profile.check_round(*_round_mutant(n, change))


def test_the_rounds_cite_the_registered_contract_brief_and_publish_the_lanes_records():
    brief = profile._verified(profile.CONTRACT_BRIEF)
    for n, (record_raw, identity_raw) in zip(profile.ROUNDS, _rounds()):
        record, identity = json.loads(record_raw), json.loads(identity_raw)
        assert record["briefSha256"] == identity["briefSha256"] == profile.digest(brief)
        assert identity["record"]["path"] == profile.REVIEW_RECORDS[n - 1]
        assert identity["ruling"]["decision"] == "KEEP" and identity["ruling"]["by"] == "LANE_MONITOR"
    assert profile.ROUND_VERDICTS[-1] == "PASS_FOR_ADOPTION"
    assert [commit[:8] for commit in profile.ROUND_SUBJECTS] == ["6cc40a1e", "4a310a82", "b8049763"]


INDEX_CHANGES = ["schema", "packet", "series", "base", "digest", "identity_digest", "path", "dropped", "extra",
                 "rounds_bytes", "not_dict"]


def _index_mutant(change):
    index, rounds = _load(profile.SOURCE_INDEX), _rounds()
    rows = index["inTreeRounds"]
    if change == "schema":
        index["schemaVersion"] = "planeon.internal.policy-observation-digests-v2-index/v2"
    elif change == "packet":
        index["packet"] = "MET-ENFORCE-041"
    elif change == "series":
        index["series"] = "MET-ENFORCE-042/packet"
    elif change == "base":
        index["baseMain"] = profile.BASE_COMMIT
    elif change == "digest":
        rows[1]["recordSha256"] = _flip(rows[1]["recordSha256"])
    elif change == "identity_digest":
        rows[2]["identitySha256"] = _flip(rows[2]["identitySha256"])
    elif change == "path":
        rows[0]["record"] = profile.REVIEW_RECORDS[1]
    elif change == "dropped":
        rows.pop()
    elif change == "extra":
        rows.append(dict(rows[-1], round=4))
    elif change == "rounds_bytes":
        rounds[0] = (rounds[0][0] + b" ", rounds[0][1])
    else:
        index = list(index.items())
    return index, rounds


@pytest.mark.parametrize("change", INDEX_CHANGES)
def test_the_source_index_names_the_in_tree_rounds(change):
    profile.check_source_index(_load(profile.SOURCE_INDEX), _rounds())
    with pytest.raises(ValueError, match="the source index names this packet's in-tree rounds"):
        profile.check_source_index(*_index_mutant(change))


ORACLE_MESSAGE = "the oracle identity binds the D5a oracle test, with ruling KEEP by the lane monitor"
ORACLE_CHANGES = ["schema", "file_path", "file_digest", "candidate", "decision", "by", "ref", "date", "test_bytes",
                  "not_bytes", "other_test"]


def _oracle_mutant(change):
    identity_raw, test_raw = profile._verified(profile.ORACLE_IDENTITY), profile._verified(profile.ORACLE_TEST)
    identity = json.loads(identity_raw)
    if change == "schema":
        identity["schemaVersion"] = "planeon.oracle-identity/v2"
    elif change == "file_path":
        identity["file"]["path"] = profile.HEAD_TEST
    elif change == "file_digest":
        identity["file"]["sha256"] = _flip(identity["file"]["sha256"])
    elif change == "candidate":
        identity["candidateCommit"] = "ee14d28e214842b5f6d9254ee88a38949e973dc8"
    elif change == "decision":
        identity["ruling"]["decision"] = "REWRITE"
    elif change == "by":
        identity["ruling"]["by"] = "OWNER"
    elif change == "ref":
        identity["ruling"]["ref"] = identity["ruling"]["ref"].split("; ")[0]
    elif change == "date":
        identity["ruling"]["date"] = "2026-10-24"
    elif change == "test_bytes":
        return identity_raw, test_raw + b"\n"
    elif change == "not_bytes":
        return identity_raw.decode("utf-8"), test_raw
    else:
        return identity_raw, profile._verified("tests/test_policy_observation_digests_oracle.py")
    return _encode(identity), test_raw


@pytest.mark.parametrize("change", ORACLE_CHANGES)
def test_the_oracle_identity_binds_its_test_with_keep(change):
    profile.check_oracle_identity(profile._verified(profile.ORACLE_IDENTITY), profile._verified(profile.ORACLE_TEST))
    assert profile.ORACLE_RULING["ref"] == "MON-I01S-ORACLE-KEEP; MON-I01S-ORACLE-REFUSAL-FORM"
    assert _load(profile.ORACLE_IDENTITY)["candidateCommit"] == profile.ORACLE_COMMIT
    with pytest.raises(ValueError, match=re.escape(ORACLE_MESSAGE)):
        profile.check_oracle_identity(*_oracle_mutant(change))


# The model over its vectors and admission v4's rendering --------------------------------------------------------------

REPLAY_MESSAGE = "the model replays its vectors with 323 checks, the complete positive's 8 among them"
REPLAY_CHANGES = ["fewer", "more", "text", "boolean", "helper_dropped", "relation_dropped", "projection_dropped",
                  "observation_added", "contract_path", "contract_digest", "definitions_changed", "definitions_not_bytes"]


def _replay_mutant(change):
    count, vectors, definitions = _replay_count(), _load(profile.VECTORS_PATH), profile._verified(profile.DEFINITIONS_PATH)
    rows = vectors["vectors"]
    if change == "fewer":
        count = count - 1
    elif change == "more":
        count = count + 1
    elif change == "text":
        count = str(count)
    elif change == "boolean":
        count = True
    elif change == "helper_dropped":
        vectors["helpers"].pop()
    elif change == "relation_dropped":
        row = [row for row in rows if row["expect"].get("same")][0]
        del row["expect"]["same"]
    elif change == "projection_dropped":
        row = [row for row in rows if row["expect"].get("projections")][0]
        row["expect"]["projections"].popitem()
    elif change == "observation_added":
        row = [row for row in rows if "observation" not in row["expect"]][0]
        row["expect"]["observation"] = []
    elif change == "contract_path":
        vectors["contract"]["path"] = "architecture/policy-observation-digests/definitions.json"
    elif change == "contract_digest":
        vectors["contract"]["canonicalSha256"] = _flip(vectors["contract"]["canonicalSha256"])
    elif change == "definitions_changed":
        changed = json.loads(definitions)
        changed["schemaVersion"] = changed["schemaVersion"] + "x"
        definitions = _encode(changed)
    else:
        definitions = definitions.decode("utf-8")
    return count, vectors, definitions


@pytest.mark.parametrize("change", REPLAY_CHANGES)
def test_the_model_replays_its_vectors_with_323_checks(change):
    vectors = _load(profile.VECTORS_PATH)
    profile.check_replay(_replay_count(), vectors, profile._verified(profile.DEFINITIONS_PATH))
    assert _replay_count() == profile.MODEL_CHECKS == 323
    assert len(vectors["helpers"]) == 16 and profile._vector_checks(vectors) == 298 and len(vectors["vectors"]) == 152
    # A re-encoding of definitions.json keeps its canonical pin.
    profile.check_replay(_replay_count(), vectors, _encode(_load(profile.DEFINITIONS_PATH)))
    with pytest.raises(ValueError, match=re.escape(REPLAY_MESSAGE)):
        profile.check_replay(*_replay_mutant(change))


def test_a_changed_vector_makes_the_model_refuse():
    vectors = _load(profile.VECTORS_PATH)
    row = [row for row in vectors["vectors"] if row["id"] == profile.UNIT_VECTOR][0]
    row["expect"]["projections"]["admissionPolicy"]["digest"] = _flip(row["expect"]["projections"]["admissionPolicy"]["digest"])
    with pytest.raises(ValueError, match="vector P-UNIT admissionPolicy digest"):
        _models()[0].check_vectors(vectors, _frozen_files())
    files = _frozen_files()
    files[profile.V4_MODEL] = files[profile.V4_MODEL] + b"\n"
    with pytest.raises(ValueError, match=re.escape("frozen model differs: " + profile.V4_MODEL)):
        _models()[0].check_vectors(_load(profile.VECTORS_PATH), files)


SEALED_MESSAGE = "the model's sealed namespace and admission v4's rendering are v4's sealed planeon-a2.json"
SEALED_CHANGES = ["raw", "rendered", "both", "hash", "namespace", "v4_namespace", "v4_cidr", "snapshot", "qual_namespace",
                  "qual_values", "qual_pin", "not_bytes", "unit_rendering"]


def _sealed():
    vectors = _load(profile.VECTORS_PATH)
    v4 = _models()[5]
    namespace = profile._module_constant(profile._verified(profile.MODEL_PATH), "SEALED_NAMESPACE")
    qual = vectors["fixtures"]["snapshots"][profile.COMPLETE_SNAPSHOT]
    raw = profile._verified(profile.V4_SEALED)
    rendered = v4.manifest_file_bytes(dict(qual["configuration"]["sealedAdmission"], namespace=namespace))
    return [raw, rendered, v4.manifest_directory_hash({profile.SEALED_NAME: raw}), namespace,
            _load(profile.V4_VECTORS)["sealed"], vectors["complete"]["snapshot"], qual]


def _sealed_mutant(change):
    args = _sealed()
    raw, qual = args[0], args[6]
    if change == "raw":
        args[0] = raw + b" "
    elif change == "rendered":
        args[1] = args[1] + b" "
    elif change == "both":
        args[0], args[1] = raw + b"\n", raw + b"\n"
    elif change == "hash":
        args[2] = _flip(args[2])
    elif change == "namespace":
        args[3] = "unit-namespace"
    elif change == "v4_namespace":
        args[4]["namespace"] = "unit-namespace"
    elif change == "v4_cidr":
        args[4]["serviceCIDR"] = "10.0.0.0/16"
    elif change == "snapshot":
        args[5] = "closure"
    elif change == "qual_namespace":
        qual["configuration"]["qualificationNamespace"] = "unit-namespace"
    elif change == "qual_values":
        qual["configuration"]["sealedAdmission"]["defaultTolerationSeconds"] = 301
    elif change == "qual_pin":
        qual["configuration"]["pinnedManifestHash"] = profile.UNIT_FENCE
    elif change == "not_bytes":
        args[0], args[1] = raw.decode("utf-8"), raw.decode("utf-8")
    else:
        args[1] = _models()[5].manifest_file_bytes(dict(profile.SEALED_VALUES, namespace="unit-namespace"))
    return args


@pytest.mark.parametrize("change", SEALED_CHANGES)
def test_the_sealed_namespace_and_rendering_are_admission_v4s(change):
    profile.check_sealed(*_sealed())
    with pytest.raises(ValueError, match=re.escape(SEALED_MESSAGE)):
        profile.check_sealed(*_sealed_mutant(change))


def test_the_layers_sealed_namespace_is_the_models_own():
    model = _models()[0]
    raw = profile._verified(profile.MODEL_PATH)
    assert profile._module_constant(raw, "SEALED_NAMESPACE") == model.SEALED_NAMESPACE == profile.SEALED_NAMESPACE
    assert profile._module_constant(raw, "NO_SUCH_NAME") is None
    assert profile._module_constant(raw + b"\nSEALED_NAMESPACE = 'x'\n", "SEALED_NAMESPACE") is None
    assert profile._module_constant(b"SEALED_NAMESPACE = f()\n", "SEALED_NAMESPACE") is None
    assert len(profile._verified(profile.V4_SEALED)) == profile.SEALED_SIZE == 8322
    assert _load(profile.V4_VECTORS)["sealed"] == dict(profile.SEALED_VALUES, namespace=profile.SEALED_NAMESPACE)


BINDING_MESSAGE = "B-I01S-1: the v2 complete binding is v1's with its two named members changed and v1's profileDigest"
BINDING_CHANGES = ["profile_digest", "both_profile_digests", "fence", "admission_digest", "other_member", "member_added",
                   "member_removed", "unit_digest", "unit_missing", "op_profile_digest", "op_below_profile_digest",
                   "op_whole_binding", "rows_not_list", "not_dict"]


def _binding():
    vectors = _load(profile.VECTORS_PATH)
    unit = [row for row in vectors["vectors"] if row["id"] == profile.UNIT_VECTOR][0]
    return [vectors["fixtures"]["bindings"]["complete"], _load(profile.V1_VECTORS)["fixtures"]["bindings"]["complete"],
            unit["expect"]["projections"]["admissionPolicy"]["digest"], vectors["vectors"]]


def _binding_mutant(change):
    args = _binding()
    binding, v1, rows = args[0], args[1], args[3]
    if change == "profile_digest":
        binding["profileDigest"] = "sha256:" + _flip(binding["profileDigest"][7:])
    elif change == "both_profile_digests":
        binding["profileDigest"] = v1["profileDigest"] = "sha256:" + _flip(binding["profileDigest"][7:])
    elif change == "fence":
        binding["enforcementPins"]["admissionFenceDigest"] = profile.DIRECTORY_HASH
    elif change == "admission_digest":
        binding["projections"]["admissionPolicy"]["projectionDigest"] = "sha256:" + "0" * 64
    elif change == "other_member":
        binding["projections"]["resourceQuota"]["projectionDigest"] = "sha256:" + "0" * 64
    elif change == "member_added":
        binding["note"] = "x"
    elif change == "member_removed":
        del binding["enforcementPins"]["hostPreflightDigest"]
    elif change == "unit_digest":
        args[2] = "sha256:" + "0" * 64
    elif change == "unit_missing":
        args[2] = None
    elif change == "op_profile_digest":
        rows[0]["ops"].append({"op": "set", "path": ["binding", "profileDigest"], "value": "sha256:" + "0" * 64})
    elif change == "op_below_profile_digest":
        rows[0]["ops"].append({"op": "delete", "path": ["binding", "profileDigest", "x"]})
    elif change == "op_whole_binding":
        rows[0]["ops"].append({"op": "set", "path": ["binding"], "value": {}})
    elif change == "rows_not_list":
        args[3] = tuple(rows)
    else:
        args[0] = list(binding.items())
    return args


@pytest.mark.parametrize("change", BINDING_CHANGES)
def test_b_i01s_1_the_complete_binding_is_v1s_with_two_members_changed(change):
    profile.check_binding(*_binding())
    binding, v1, unit, rows = _binding()
    assert profile._changed_members(v1, binding) == [("enforcementPins", "admissionFenceDigest"),
                                                     ("projections", "admissionPolicy", "projectionDigest")]
    assert binding["profileDigest"] == v1["profileDigest"] == profile.V1_PROFILE_DIGEST
    assert binding["enforcementPins"]["admissionFenceDigest"] == profile.UNIT_FENCE
    assert not any(op["path"][:1] == ["binding"] for row in rows for op in row["ops"] if "profileDigest" in op["path"])
    with pytest.raises(ValueError, match=re.escape(BINDING_MESSAGE)):
        profile.check_binding(*_binding_mutant(change))


def test_the_member_diff_names_each_difference():
    assert profile._changed_members({"a": 1, "b": {"c": 2}}, {"a": 1, "b": {"c": 3}, "d": 4}) == [("b", "c"), ("d",)]
    assert profile._changed_members([1], [1]) == [] and profile._changed_members(1, "1") == [()]
    assert profile._sets_profile_digest({"path": ["binding"]}) and not profile._sets_profile_digest(
        {"path": ["binding", "profile"]})


# Edge record v11 ---------------------------------------------------------------------------------------------------

EDGE_MESSAGE = ("edge record v11 is v10's members and 72 rows with exactly the seven new rows, superseding v10 by "
                "digest")
EDGE_CHANGES = ["v10_row", "v10_order", "row_dropped", "row_extra", "row_sha", "row_mode", "row_commit", "row_packet",
                "row_consumer", "row_relation", "row_status", "supersedes_digest", "supersedes_packet", "carried",
                "member_order", "artifact", "v10_bytes", "rows_from_other_bytes", "not_dict"]


def _edge():
    files = {path: profile._verified(path) for path, _commit, _consumer, _packet in profile.EDGE_ROWS}
    modes = {path: profile.reviewed_mode(path) for path in files}
    v10_raw = profile._verified(profile.EDGE_V10)
    return [_load(profile.EDGE_V11), json.loads(v10_raw), v10_raw, profile._edge_rows(files, modes)]


def _edge_mutant(change):
    args = _edge()
    v11 = args[0]
    v11_rows = v11["artifacts"]
    if change == "v10_row":
        v11_rows[5]["status"] = "RETIRED"
    elif change == "v10_order":
        v11_rows[0], v11_rows[1] = v11_rows[1], v11_rows[0]
    elif change == "row_dropped":
        v11_rows.pop()
    elif change == "row_extra":
        v11_rows.append(dict(v11_rows[-1]))
    elif change == "row_sha":
        v11_rows[72]["sha256"] = _flip(v11_rows[72]["sha256"])
    elif change == "row_mode":
        v11_rows[73]["mode"] = "100755"
    elif change == "row_commit":
        v11_rows[74]["providerCommit"] = profile.ON_MAIN_COMMIT
    elif change == "row_packet":
        v11_rows[75]["providerPacket"] = profile.NEW_PACKET
    elif change == "row_consumer":
        v11_rows[76]["consumerPacket"] = "HE-004-I01B"
    elif change == "row_relation":
        v11_rows[77]["relation"] = "DERIVED"
    elif change == "row_status":
        v11_rows[78]["status"] = "IN_USE"
    elif change == "supersedes_digest":
        v11["supersedes"]["sha256"] = "sha256:" + _flip(v11["supersedes"]["sha256"][7:])
    elif change == "supersedes_packet":
        v11["supersedes"]["packet"] = "MET-ENFORCE-040"
    elif change == "carried":
        v11["rules"] = v11["rules"][:-1]
    elif change == "member_order":
        args[0] = dict(reversed(list(v11.items())))
    elif change == "artifact":
        v11["artifact"] = args[1]["artifact"]
    elif change == "v10_bytes":
        args[2] = args[2] + b" "
    elif change == "rows_from_other_bytes":
        args[3][2]["sha256"] = profile.digest(profile._verified(profile.README_PATH) + b"\n")
    else:
        args[0] = list(v11.items())
    return args


@pytest.mark.parametrize("change", EDGE_CHANGES)
def test_edge_record_v11_is_v10_with_the_seven_new_rows(change):
    profile.check_edge(*_edge())
    v11, v10, _raw, rows = _edge()
    assert len(v10["artifacts"]) == 72 and len(v11["artifacts"]) == 79 and len(rows) == 7
    assert [row["consumerPacket"] for row in rows] == ["HE-004-I01B4"] * 7
    assert [row.get("providerPacket") for row in rows] == ["MET-ENFORCE-042"] * 3 + [None] * 4
    assert [row["providerCommit"] for row in rows] == [None] * 3 + [profile.ON_MAIN_COMMIT] * 4
    assert v11["supersedes"]["sha256"] == "sha256:a4fad53dfadbe8a5d79d4049fbba83173adaacec8d33df5ca377aa288539364e"
    with pytest.raises(ValueError, match=re.escape(EDGE_MESSAGE)):
        profile.check_edge(*_edge_mutant(change))


# The pins and classes (B-L1-4) -----------------------------------------------------------------------------------------

PINS_MESSAGE = "the mechanics pins record is closed"
PINS_CHANGES = ["schema", "extra_member", "missing_member", "member_order", "unsorted", "duplicate", "row_key", "row_sha",
                "lists_empty", "lists_label", "rule", "counts", "registry_row_keys", "registry_row_rule", "class_rows",
                "class_two_forms", "class_prefix", "class_name", "class_source", "class_extra_key", "not_dict"]


def _pins_mutant(change):
    record = _pins()
    pins, rows = record["unchangedPins"], record["evolutionSurfaceClasses"]
    registry_row = [row for row in pins if row["rule"] == "BASE_ENTRIES"][0]
    if change == "schema":
        record["schemaVersion"] = "planeon.internal.policy-observation-digests-v2-pins/v2"
    elif change == "extra_member":
        record["mechanicsBase"] = profile.BASE_COMMIT
    elif change == "missing_member":
        del record["evolutionSurfaceClasses"]
    elif change == "member_order":
        record = dict(reversed(list(record.items())))
    elif change == "unsorted":
        pins[0], pins[1] = pins[1], pins[0]
    elif change == "duplicate":
        pins.insert(1, dict(pins[0]))
    elif change == "row_key":
        pins[0]["note"] = "x"
    elif change == "row_sha":
        pins[0]["sha256"] = pins[0]["sha256"].upper()
    elif change == "lists_empty":
        pins[0]["lists"] = []
    elif change == "lists_label":
        pins[0]["lists"] = ["F9.9"]
    elif change == "rule":
        pins[0]["rule"] = "UNCHANGED"
    elif change == "counts":
        [row for row in pins if row["rule"] == "BYTE_IDENTICAL"][0]["rule"] = "STEP_RULE"
    elif change == "registry_row_keys":
        del registry_row["entries"]
    elif change == "registry_row_rule":
        registry_row["rule"] = "BYTE_IDENTICAL"
    elif change == "class_rows":
        rows.pop()
    elif change == "class_two_forms":
        rows[0]["pattern"] = profile.CONTRACT_DIR + "review-round<n>.json"
        del rows[0]["source"]
    elif change == "class_prefix":
        rows[0] = {"prefix": profile.CONTRACT_DIR, "class": rows[0]["class"], "source": rows[0]["source"]}
    elif change == "class_name":
        rows[0]["class"] = "GATE_LEGAL"
    elif change == "class_source":
        rows[0]["source"] = "THE_AUTHOR"
    elif change == "class_extra_key":
        rows[0]["note"] = "x"
    else:
        record = list(record.items())
    return record


@pytest.mark.parametrize("change", PINS_CHANGES)
def test_the_pins_record_is_closed(change):
    profile.check_pins_record(_pins())
    with pytest.raises(ValueError, match=re.escape(PINS_MESSAGE)):
        profile.check_pins_record(_pins_mutant(change))


PIN_MESSAGE = "an unchangedPins row holds at this era: "


def _pin_inputs(row):
    raw = profile._verified(row["path"]) if row["rule"] == "BYTE_IDENTICAL" else None
    return row, raw, _changed_rules().get(row["path"])


@pytest.mark.parametrize("index", range(253))
def test_every_pin_holds_at_this_era(index):
    row, raw, rule = _pin_inputs(_pins()["unchangedPins"][index])
    profile.check_pin(row, raw, rule)
    if row["rule"] == "BYTE_IDENTICAL":
        assert rule is None and profile.digest(raw) == row["sha256"] == profile.ERA_SHA256[row["path"]]
        mutants = [(dict(row, sha256=_flip(row["sha256"])), raw, rule), (row, raw + b" ", rule), (row, None, rule),
                   (row, raw, {"beforeSha256": row["sha256"]}), (dict(row, rule="STEP_RULE"), raw, rule)]
    elif row["rule"] == "STEP_RULE":
        assert rule is not None and rule["beforeSha256"] == row["sha256"] and row["path"] not in profile.ERA_SHA256
        mutants = [(row, raw, None), (row, raw, dict(rule, beforeSha256=_flip(rule["beforeSha256"]))),
                   (dict(row, path="architecture/proxy-contract-amendment.json"), raw, rule),
                   (dict(row, sha256=_flip(row["sha256"])), raw, rule), (dict(row, rule="BYTE_IDENTICAL"), raw, rule)]
    else:
        assert row["path"] == profile.REGISTRY_PATH and rule is not None and row["entries"] == 10
        mutants = [(row, raw, None), (dict(row, entries=11), raw, rule), (dict(row, entries="10"), raw, rule),
                   (dict(row, path=profile.PACKET_BRIEF), raw, rule), (dict(row, lists=["LRR"]), raw, rule),
                   (dict(row, rule="STEP_RULE"), raw, rule)]
    for args in mutants:
        with pytest.raises(ValueError, match=re.escape(PIN_MESSAGE)):
            profile.check_pin(*args)


def test_the_pins_are_section_2s_untouched_list():
    pins = _pins()["unchangedPins"]
    assert [row["path"] for row in pins if row["rule"] == "STEP_RULE"] == [
        "scripts/validate_policy_observation_digests.py", "tests/test_policy_observation_digests.py"]
    labels = {label for row in pins for label in row["lists"]}
    assert labels == set(profile.PIN_LISTS)
    counts = {label: len([row for row in pins if label in row["lists"]]) for label in profile.PIN_LISTS}
    assert counts == {"POD1": 18, "PODM": 1, "PODO": 1, "PODA": 1, "PODL": 1, "PODT": 1, "AS3M": 1, "I06M": 3,
                      "NQ4M": 1, "I06IN": 3, "CS": 1, "PV": 1, "RD": 1, "PPS": 1, "PPV": 1, "BASELINE": 1, "PCA": 1,
                      "EDGES": 20, "ADM2": 17, "ADM3": 6, "ADM4": 6, "PP2": 5, "LPKP": 1, "LRR": 169, "REGISTRY": 1}
    legacy = json.loads(profile.regular_bytes("architecture/review-record/legacy-review-records.json"))
    frozen = {row["path"]: row["sha256"] for row in legacy["entries"]}
    for row in pins:
        if "LRR" in row["lists"]:
            assert frozen[row["path"]] == row["sha256"]
    registry_row = [row for row in pins if row["rule"] == "BASE_ENTRIES"][0]
    base = profile._undo_this_layer(profile.REGISTRY_PATH, profile._verified(profile.REGISTRY_PATH))
    assert registry_row["sha256"] == profile.digest(profile.canonical(json.loads(base)["briefs"]))
    paths = {row["path"] for row in pins}
    for path in (profile.V1_STATUS, profile.V1_VECTORS, profile.EDGE_V10, "architecture/artifact-edges/README.md",
                 "architecture/artifact-edges/operator-harness-engineering.json", "architecture/proxy-contract-amendment.json",
                 "architecture/linux-probe-kit-admission/mechanics-pins.json", "architecture/policy-observation-digests-authority.json"):
        assert path in paths


CLASS_MESSAGE = "every evolution-surface class row resolves to its class at this era"
CLASS_CHANGES = ["class", "resolved", "uncovered", "leading_zero", "paths_not_list", "resolved_not_dict"]


def _classes():
    surface, record = _models()[7], _load(profile.SURFACE_RECORD)
    rows, paths = _pins()["evolutionSurfaceClasses"], _changed()
    resolved = {path: surface.resolve(record, path) for row in rows for path in profile.class_paths(row, paths)}
    return rows, paths, resolved


def _classes_mutant(change):
    rows, paths, resolved = _classes()
    if change == "class":
        rows[-1]["class"] = "ORACLE_TESTS"
    elif change == "resolved":
        resolved[profile.REVIEW_RECORDS[0]] = "CONTRACT_AND_SOURCE"
    elif change == "uncovered":
        rows[0]["path"] = profile.CONTRACT_DIR + "README.txt"
    elif change == "leading_zero":
        rows.append({"pattern": profile.CONTRACT_DIR + "review-round0<n>.json", "class": "REVIEW_RECORD",
                     "source": "DESIGN_REV3_SECTION_2"})
    elif change == "paths_not_list":
        paths = tuple(paths)
    else:
        resolved = list(resolved.items())
    return rows, paths, resolved


@pytest.mark.parametrize("change", CLASS_CHANGES)
def test_every_class_row_resolves_to_its_class(change):
    profile.check_classes(*_classes())
    with pytest.raises(ValueError, match=re.escape(CLASS_MESSAGE)):
        profile.check_classes(*_classes_mutant(change))


def test_the_class_rows_cover_section_2s_table_by_form():
    rows, paths, resolved = _classes()
    by_class = {}
    for row in rows:
        for path in profile.class_paths(row, paths):
            by_class.setdefault(row["class"], set()).add(path)
    assert by_class["REVIEW_RECORD"] == set(profile.REVIEW_RECORDS)
    assert by_class["ORACLE_TESTS"] == {profile.ORACLE_TEST}
    assert by_class["GATE_REVIEW_PROCESS"] == {profile.REGISTRY_PATH}
    assert set(profile.REVIEW_IDENTITIES) | {profile.PINS_PATH, profile.PACKET_PATH, profile.AUTHORITY_PATH,
                                             profile.VALIDATOR_PATH, profile.HEAD_TEST, profile.MODEL_PATH,
                                             profile.EDGE_V11, profile.EDGE_README} | set(
        profile.LIVING_CATALOGS) <= by_class["CONTRACT_AND_SOURCE"]
    assert profile.class_paths({"pattern": profile.CONTRACT_DIR + "review-round<n>.json"},
                               [profile.CONTRACT_DIR + "review-round01.json", profile.CONTRACT_DIR + "review-round1.json",
                                profile.CONTRACT_DIR + "review-round.json", profile.CONTRACT_DIR + "review-roundx.json"]) == [
        profile.CONTRACT_DIR + "review-round1.json"]
    assert len(rows) == profile.CLASS_ROWS == 21


# The registry, the gate list and the gate hits -------------------------------------------------------------------------

REGISTRY_MESSAGE = ("the registry is the base's ten entries followed by exactly this packet's two entries, each pinning "
                    "its brief")
REGISTRY_CHANGES = ["registry_bytes", "base_bytes", "packet_brief_bytes", "contract_brief_bytes", "not_bytes",
                    "briefs_not_dict", "contract_dropped", "packet_kind", "contract_digest", "contract_version",
                    "extra_series", "order", "base_entry_changed", "base_entry_dropped", "kinds", "schema",
                    "serialization", "pin_digest", "pin_entries", "pin_missing"]


def _registry():
    raw = profile._verified(profile.REGISTRY_PATH)
    pin = [row for row in _pins()["unchangedPins"] if row["path"] == profile.REGISTRY_PATH][0]
    return [raw, profile._undo_this_layer(profile.REGISTRY_PATH, raw),
            {path: profile._verified(path) for path in (profile.PACKET_BRIEF, profile.CONTRACT_BRIEF)}, pin]


def _registry_mutant(change):
    args = _registry()
    raw = args[0]
    if change == "registry_bytes":
        args[0] = raw + b" "
        return args
    if change == "base_bytes":
        args[1] = args[1] + b" "
        return args
    if change == "packet_brief_bytes":
        args[2][profile.PACKET_BRIEF] = args[2][profile.PACKET_BRIEF] + b" "
        return args
    if change == "contract_brief_bytes":
        args[2][profile.CONTRACT_BRIEF] = args[2][profile.CONTRACT_BRIEF] + b" "
        return args
    if change == "not_bytes":
        args[0] = raw.decode("utf-8")
        return args
    if change == "briefs_not_dict":
        args[2] = list(args[2].values())
        return args
    if change == "pin_digest":
        args[3] = dict(args[3], sha256=_flip(args[3]["sha256"]))
        return args
    if change == "pin_entries":
        args[3] = dict(args[3], entries=11)
        return args
    if change == "pin_missing":
        args[3] = None
        return args
    registry = json.loads(raw)
    entries = registry["briefs"][-2:]
    if change == "contract_dropped":
        registry["briefs"].remove(entries[1])
    elif change == "packet_kind":
        entries[0]["kind"] = "CONTRACT"
    elif change == "contract_digest":
        entries[1]["sha256"] = _flip(entries[1]["sha256"])
    elif change == "contract_version":
        entries[1]["version"] = 2
    elif change == "extra_series":
        registry["briefs"].append(dict(entries[1], series="MET-ENFORCE-042/design"))
    elif change == "order":
        registry["briefs"][-2:] = [entries[1], entries[0]]
    elif change == "base_entry_changed":
        registry["briefs"][0]["series"] = registry["briefs"][0]["series"] + "x"
    elif change == "base_entry_dropped":
        del registry["briefs"][9]
    elif change == "kinds":
        registry["kinds"]["PACKET"]["passing"] = ["PASS_FOR_PRECHECK"]
    elif change == "schema":
        registry["schemaVersion"] = "planeon.review-briefs/v2"
    else:
        args[0] = (json.dumps(registry, indent=2) + "\n").encode("ascii")
        return args
    args[0] = (json.dumps(registry, indent=1) + "\n").encode("ascii")
    return args


@pytest.mark.parametrize("change", REGISTRY_CHANGES)
def test_the_registry_is_the_bases_with_this_packets_two_series(change):
    profile.check_registry(*_registry())
    registry = json.loads(profile._verified(profile.REGISTRY_PATH))
    assert len(registry["briefs"]) == 12
    assert [row["series"] for row in registry["briefs"][-4:]] == [
        "MET-LINUX-009/packet", "MET-LINUX-009/contract", "MET-ENFORCE-042/packet", "MET-ENFORCE-042/contract"]
    assert profile.digest(_registry()[1]) == profile.BASE_REGISTRY_SHA256
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


GATE_MESSAGE = "the gate paths among the packet's changed files are exactly the registry"


def _hits_mutant(change):
    changed = _changed()
    if change == "no_registry":
        changed.remove(profile.REGISTRY_PATH)
    elif change == "surface_record":
        changed = sorted(changed + [profile.SURFACE_RECORD])
    elif change == "gate_prefix":
        changed = sorted(changed + ["ci/linux-runner/runner.py"])
    elif change == "case_variant":
        changed = sorted(changed + ["Architecture/Review-Record/README.md"])
    elif change == "schema":
        changed = sorted(changed + ["schemas/x.schema.json"])
    elif change == "harness_docs":
        changed = sorted(changed + ["docs/harnesses/x.md"])
    elif change == "unsorted":
        changed.reverse()
    else:
        changed = tuple(changed)
    return _gate(), changed


@pytest.mark.parametrize("change", ["no_registry", "surface_record", "gate_prefix", "case_variant", "schema",
                                    "harness_docs", "unsorted", "not_list"])
def test_the_packets_changed_files_hold_exactly_the_registry_as_gate_path(change):
    gate, changed = _gate(), _changed()
    profile.check_gate_hits(gate, changed)
    assert profile.gate_paths(gate, changed) == [profile.REGISTRY_PATH]
    surface = _models()[7]
    record = _load(profile.SURFACE_RECORD)
    # Gate material through the registry alone: the owner approves this packet's exact head.
    assert surface.pr_approvers(record, changed) == ["OWNER"]
    assert surface.resolve(record, profile.REGISTRY_PATH) == "GATE_REVIEW_PROCESS"
    assert surface.resolve(record, profile.ORACLE_TEST) == "ORACLE_TESTS"
    for path in profile.REVIEW_RECORDS:
        assert surface.resolve(record, path) == "REVIEW_RECORD"
    for path in profile.NEW_FILES + (profile.HEAD_TEST, profile.VALIDATOR_PATH, profile.AUTHORITY_PATH,
                                     profile.PACKET_PATH) + profile.LIVING_CATALOGS:
        if path not in profile.REVIEW_RECORDS and path != profile.ORACLE_TEST:
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

SEMANTIC_FUNCTIONS = {"_era_bytes", "_verified", "check_era_models", "check_freeze", "check_new_files",
                      "check_added_file", "check_status", "check_round", "check_source_index", "check_oracle_identity",
                      "check_replay", "check_sealed", "check_binding", "check_edge", "check_pins_record", "check_pin",
                      "check_classes", "check_registry", "check_gate_list", "check_gate_hits"}
CHECK_TESTS = {
    "MET-ENFORCE-042 reviewed bytes are bound: ": "test_a_path_outside_the_era_is_refused_before_it_is_read",
    "unreviewed DIGEST-CONTRACT-V2 source: ": "test_every_era_file_is_bound_by_digest",
    ERA_MODELS_MESSAGE: "test_the_model_runs_this_eras_frozen_models",
    FREEZE: "test_the_freeze_refuses_every_other_change",
    "this packet adds exactly its contract files, model, edge record, oracle test and layer test, each once":
        "test_the_packet_adds_exactly_its_files_each_once",
    "a file this packet adds is a regular file of git mode 100644: ":
        "test_an_added_file_is_a_regular_file_of_mode_100644_without_a_local_path",
    "no absolute local path in a file this packet adds: ":
        "test_an_added_file_is_a_regular_file_of_mode_100644_without_a_local_path",
    STATUS_MESSAGE: "test_the_status_is_closed_and_records_the_adoption",
    "a CONTRACT round is bound to its published record and identity: round ":
        "test_each_contract_round_is_bound_to_its_record_and_identity",
    "the source index names this packet's in-tree rounds": "test_the_source_index_names_the_in_tree_rounds",
    ORACLE_MESSAGE: "test_the_oracle_identity_binds_its_test_with_keep",
    REPLAY_MESSAGE: "test_the_model_replays_its_vectors_with_323_checks",
    SEALED_MESSAGE: "test_the_sealed_namespace_and_rendering_are_admission_v4s",
    BINDING_MESSAGE: "test_b_i01s_1_the_complete_binding_is_v1s_with_two_members_changed",
    EDGE_MESSAGE: "test_edge_record_v11_is_v10_with_the_seven_new_rows",
    PINS_MESSAGE: "test_the_pins_record_is_closed",
    PIN_MESSAGE: "test_every_pin_holds_at_this_era",
    CLASS_MESSAGE: "test_every_class_row_resolves_to_its_class",
    REGISTRY_MESSAGE: "test_the_registry_is_the_bases_with_this_packets_two_series",
    "the evolution surface record derives 31 exact or prefix gate entries":
        "test_the_gate_list_is_31_exact_or_prefix_entries",
    GATE_MESSAGE: "test_the_packets_changed_files_hold_exactly_the_registry_as_gate_path",
    "unreviewed current source: ": "test_the_canonical_check_reads_this_eras_bytes",
    "canonical byte-minimal inverse hunks: ": "test_whole_line_hunks_are_refused_where_canonical_ones_differ"}
NAMED_MESSAGES = {ERA_MODELS_MESSAGE: "ERA_MODELS_MESSAGE", FREEZE: "FREEZE", STATUS_MESSAGE: "STATUS_MESSAGE",
                  ORACLE_MESSAGE: "ORACLE_MESSAGE", REPLAY_MESSAGE: "REPLAY_MESSAGE", SEALED_MESSAGE: "SEALED_MESSAGE",
                  BINDING_MESSAGE: "BINDING_MESSAGE", EDGE_MESSAGE: "EDGE_MESSAGE", PINS_MESSAGE: "PINS_MESSAGE",
                  PIN_MESSAGE: "PIN_MESSAGE", CLASS_MESSAGE: "CLASS_MESSAGE", REGISTRY_MESSAGE: "REGISTRY_MESSAGE",
                  GATE_MESSAGE: "GATE_MESSAGE"}


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


# W1 (design section 5; the contract README section 10): the layer test runs VPO's validate_messages and profile v2's
# validate and precondition on the complete I01 positive, with no skip, expected-failure mark or import guard, keeping
# v1's C1-1 shape with profile v2. `complete` is the complete I01 positive in the contract's vectors.json; CS is
# architecture/policy-observation-inputs/channel.schema.json and PPS2 profile v2's
# architecture/proxy-profile-v2/profile.schema.json. These assertions are the only executable check that the complete
# positive fits the I01 wire.

W1_VECTORS = profile.ROOT / "architecture/policy-observation-digests-v2/vectors.json"
W1_CS = profile.ROOT / "architecture/policy-observation-inputs/channel.schema.json"
W1_PPS2 = profile.ROOT / "architecture/proxy-profile-v2/profile.schema.json"
W1_P10 = "P10 the three policy references differ from the policy"


def _w1_complete():
    return json.loads(W1_VECTORS.read_bytes())["complete"]


def test_w1_validate_messages_accepts_the_complete_positive():
    """(1) validate_messages(complete.binding, complete.request, complete.observation, complete.profile, CS,
    complete.now, complete.previous) == []"""
    complete, cs = _w1_complete(), json.loads(W1_CS.read_bytes())
    assert validate_messages(complete["binding"], complete["request"], complete["observation"], complete["profile"], cs,
                             complete["now"], complete["previous"]) == []


def test_w1_profile_v2_accepts_the_complete_positive_in_the_sealed_namespace():
    """(2) proxy_profile_v2.validate(complete.profile, PPS2) == [] and proxy_profile_v2.precondition(complete.profile,
    <qual's qualificationNamespace>) == [], that namespace equal to the model's SEALED_NAMESPACE."""
    from scripts import policy_observation_digests_v2, proxy_profile_v2
    complete, schema = _w1_complete(), json.loads(W1_PPS2.read_bytes())
    snapshots = json.loads(W1_VECTORS.read_bytes())["fixtures"]["snapshots"]
    namespace = snapshots[complete["snapshot"]]["configuration"]["qualificationNamespace"]
    assert namespace == policy_observation_digests_v2.SEALED_NAMESPACE == "planeon-qual"
    assert proxy_profile_v2.validate(complete["profile"], schema) == []
    assert proxy_profile_v2.precondition(complete["profile"], namespace) == []


@pytest.mark.parametrize("kind", ["ResourceQuota", "LimitRange", "ServiceAccount"])
def test_w1_each_refuses_when_one_preexisting_reference_changes(kind):
    """(3) for each of ResourceQuota, LimitRange and ServiceAccount, a changed observedDigest in complete.profile gives
    VPO's refusal and profile v2's P10 text."""
    from scripts import proxy_profile_v2
    complete, cs, schema = _w1_complete(), json.loads(W1_CS.read_bytes()), json.loads(W1_PPS2.read_bytes())
    assert proxy_profile_v2.TEXT["P10"] == W1_P10
    references = [ref for ref in complete["profile"]["capacityEntries"]["preexistingResourceRefs"] if ref["kind"] == kind]
    assert len(references) == 1
    changed = "sha256:" + ("1" * 64 if references[0]["observedDigest"] == "sha256:" + "0" * 64 else "0" * 64)
    assert changed != references[0]["observedDigest"]
    references[0]["observedDigest"] = changed
    assert validate_messages(complete["binding"], complete["request"], complete["observation"], complete["profile"], cs,
                             complete["now"], complete["previous"]) == ["invalid protected observation data"]
    assert proxy_profile_v2.validate(complete["profile"], schema) == [W1_P10]
