"""Exact source lineage for MET-LIVE-004; workload profile v2 and admission semantics v4 (LPK-1) as one combined contract, adopted as candidate c3 after its in-tree CONTRACT rounds 1 and 2, with its D5a oracles and B-L1-4's pins record: the head keeps the full fan-in (8 own and 74 predecessor routes, every catalog walk and round trip, the full payload loop), and the semantic check (the freeze, the files added, the adoption, the rounds, the source index and the oracle identities, the models over their vectors with the sealed A2 file, the P01 text and the cross-contract group, the pins and classes, the unchanged registry, the derived gate check, and the canonical hunks) has a failing case for every refusal, each on plain data; the profile v2 schema's verdict is cross-checked with jsonschema against the model's P00."""
import ast
import json
from copy import deepcopy
import os
import re
import stat
from pathlib import Path
from types import MappingProxyType

import pytest

from scripts import validate_linux_probe_kit_admission as profile
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
    # The newer MET-LINUX-009 layer is projected away before this layer's payload checks.
    return profile.successor.historical_catalog(packets())


def changed_test():
    return next(path for path in profile._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert profile.validate() is None
    current = packets()
    accepted = profile.historical_catalog(current)
    assert len(current) == 266 and len(accepted) == 262
    assert set(accepted) == set(current) - {profile.NEW_PACKET, profile.successor.NEW_PACKET,
                                            profile.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.NEW_PACKET}
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


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "lpi_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = profile.historical_bytes(path, raw) if route in ("current_test", "old_bytes") else None
    current_packets = packets() if route == "catalog" else None
    layer = layer_packets() if route == "payloads" else None
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
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
    with pytest.raises(ValueError, match="linux probe kit admission history authority digest"):
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
    assert len(profile.historical_catalog(current)) == 262


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
    assert len(profile.historical_catalog(current)) == 262
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
    assert len(rules) == 263 and len(parsed) == 262
    assert profile._packet_rules() is rules and len(parsed) == 262
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
    with pytest.raises(ValueError, match="linux probe kit admission history authority digest"):
        profile.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = layer_packets()
    profile.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "linux-probe-kit-admission-authority.json").write_bytes(
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
    # The newer MET-LINUX-009 layer refuses a mutated validator before this layer.
    with pytest.raises(ValueError, match="unreviewed current source: scripts/validate_linux_probe_kit_admission.py"):
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
            assert all("validate_" not in alias.name or alias.name == "validate_met_linux_009"
                       for alias in node.names)


def _count_authority_reads(monkeypatch):
    counts = {}
    for module in (profile.successor, profile, lpi, lkg, pks, rrv, pod, evs, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner):
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
    expected = {module.__name__: 1 for module in (profile.successor, profile, lpi, lkg, pks, rrv, pod, evs, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner)}
    if route == "current_test":
        # The forward route reads this layer's newest bytes and then projects them forward once more.
        assert all(counts[name] >= 1 for name in expected) and set(counts) == set(expected)
    else:
        assert counts == expected


# MET-LIVE-004 (LINUX-PROBE-KIT-ADMISSION): this era's check, and a failing case for every check. Every mutant below is
# applied to plain data handed to the layer's pure checks: nothing in the layer or the library is patched or swapped. The
# mutants are built by the pure helpers _<area>_mutant(change), one change name per mutant. The three contract models and
# the evolution surface model are executed from this era's verified bytes through the layer's era loader. This test also
# reaches what the layer does not, since the names are not attribute names the frozen allow-list admits: profile v2's
# refusal table TEXT, its precondition (the layer's restated P40 must agree with it on every cross-contract case and on
# malformed data) and its schema walker schema_error, whose verdict over the positive and every negative must be
# jsonschema's (4.24.0, the pinned G-JSONSCHEMA bundle's version, MON-LPK1-SCHEMA-RUN).

VALIDATE = profile.validate_linux_probe_kit_admission
# Tamper values name paths that already exist and that this packet does not carry in the tampered place.
OTHER_PATH = "scripts/validate_linux_probe_interface.py"
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


def _lpk0():
    return profile._verified(profile.LPK0_RECORD)


def _pins():
    return _load(profile.PINS_PATH)


def _changed():
    return profile._packet_paths()


def _gate():
    return _models()[3].check(_load(profile.SURFACE_RECORD))["gateMaterial"]


def _flip(text):
    """A different lowercase hex digest of the same length."""
    return text[:-1] + ("0" if text[-1] != "0" else "1")


def _encode(value):
    return (json.dumps(value, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def test_the_contract_holds_for_this_era():
    assert VALIDATE() is None


def test_the_era_holds_the_added_files_the_pins_lpk0s_record_the_registry_and_the_surface():
    pins = [row["path"] for row in _pins()["unchangedPins"] if row["rule"] == "BYTE_IDENTICAL"]
    assert set(profile.ERA_SHA256) == set(profile.NEW_FILES) | set(pins) | {
        profile.LPK0_RECORD, profile.REGISTRY_PATH, profile.PACKET_BRIEF, profile.CONTRACT_BRIEF, profile.SURFACE_RECORD,
        profile.SURFACE_MODEL}
    assert len(profile.ERA_SHA256) == 97 and len(profile.NEW_FILES) == 21 and len(set(profile.NEW_FILES)) == 21
    assert len(pins) == 70 and not set(pins) & set(profile.NEW_FILES)
    assert {profile.V3_MODEL, profile.V3_VECTORS} <= set(pins)
    assert len(profile.CONTRACT_FILES) == 11 and len(profile.SET_FILES) == 8 and len(profile.ORACLE_TESTS) == 2
    assert profile.ERA_SHA256[profile.REGISTRY_PATH] == profile.REGISTRY_SHA256
    assert profile.ERA_SHA256[profile.V4_SEALED] == profile.SEALED_SHA256
    assert profile.ERA_SHA256[profile.LPK0_RECORD] == (
        "3de2d73e0413388ba286899cdd364c876dfbd869510c88537da8b1c91726ef8b")
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
        with pytest.raises(ValueError, match=re.escape("unreviewed LINUX-PROBE-KIT-ADMISSION source: " + path)):
            profile._era_bytes(path, changed)


def test_a_path_outside_the_era_is_refused_before_it_is_read():
    for path in (profile.SET_DIR + "notes.md", profile.V4_DIR + "admission-manifests/other.json",
                 "architecture/linux-probe-interface/binding.json", "scripts/validate_proxy_contract.py",
                 "tests/test_admission_channel_v3.py", OTHER_PATH, profile.VALIDATOR_PATH, profile.HEAD_TEST,
                 profile.LIVING_CATALOGS[0], None):
        with pytest.raises(ValueError, match="MET-LIVE-004 reviewed bytes are bound: "):
            profile._verified(path)
        with pytest.raises(ValueError, match="MET-LIVE-004 reviewed bytes are bound: "):
            profile._era_bytes(path, b"")


def test_the_era_models_are_executed_from_verified_bytes():
    assert [model.__name__ for model in _models()] == [
        "_met_live_004_admission_semantics_v4", "_met_live_004_admission_semantics_v3", "_met_live_004_proxy_profile_v2",
        "_met_live_004_evolution_surface"]
    assert [model.__file__ for model in _models()] == [str(profile.ROOT / path) for path in (
        profile.V4_MODEL, profile.V3_MODEL, profile.P2_MODEL, profile.SURFACE_MODEL)]


# The freeze and the files this packet adds -----------------------------------------------------------------------------

FREEZE = "this packet edits only chain validators, tests and the three living catalogs: "


@pytest.mark.parametrize("path", ["scripts/admission_semantics_v3.py", "scripts/admission_semantics_v4.py",
                                  "scripts/proxy_profile_v2.py", "scripts/evolution_surface.py", "scripts/review_record.py",
                                  "scripts/chain_identity.py", "architecture/admission-semantics-v3/vectors.json",
                                  "architecture/admission-semantics-v2/admission-manifests/planeon-a2.json",
                                  "architecture/proxy-contract-inputs/profile.schema.json",
                                  "architecture/proxy-contract-amendment.json",
                                  "architecture/chain-compaction/identity-rule.json",
                                  "architecture/review-record/briefs.json",
                                  "architecture/evolution-surface/evolution-surface.json",
                                  "architecture/artifact-edges/operator-harness-engineering-v10.json",
                                  "architecture/probe-kit-scope/amendment.json",
                                  "docs/alpha-2/PROXY_CONTRACT_READINESS.md", "docs/DEVELOPMENT_STATUS.md",
                                  "tests/conftest.py", "conftest.py", "scripts/validate_x/y.py", "scripts/validate_x.txt",
                                  "ci/linux-runner/runner.py", "pyproject.toml", None])
def test_the_freeze_refuses_every_other_change(path):
    changed = list(profile._PROJECTION_RULES)
    profile.check_freeze(changed)
    with pytest.raises(ValueError, match=re.escape(FREEZE)):
        profile.check_freeze(changed + [path])


def _added_mutant(change):
    added = list(profile.NEW_FILES) + [profile.HEAD_TEST]
    if change == "missing":
        added.remove(profile.V4_STATUS)
    elif change == "extra":
        added.append(profile.SET_DIR + "review-round3.json")
    elif change == "duplicate":
        added.append(profile.V4_MODEL)
    elif change == "no_head_test":
        added.remove(profile.HEAD_TEST)
    elif change == "no_pins":
        added.remove(profile.PINS_PATH)
    else:
        added = tuple(added)
    return added


@pytest.mark.parametrize("change", ["missing", "extra", "duplicate", "no_head_test", "no_pins", "not_list"])
def test_the_packet_adds_exactly_its_files_each_once(change):
    profile.check_new_files(list(profile.NEW_FILES) + [profile.HEAD_TEST])
    profile.check_new_files(list(profile.authority()["newFiles"]))
    with pytest.raises(ValueError, match="this packet adds exactly its contract files, review set, oracle tests and "
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


# The adoption: both status records, the rounds, the source index and the oracle identities -----------------------------

STATUS_CHANGES = ["schema", "packet", "work_item", "candidate", "base", "series", "state", "combined", "reviewer",
                  "native", "adoption_ruling", "adoption_commit", "record_digest", "identity_digest", "verdict",
                  "subject", "round_base", "round_dropped", "round_key_order", "lpk0_record", "lpk0_digest",
                  "extra_key", "missing_key", "key_order", "rounds_bytes", "lpk0_bytes", "not_dict"]


def _status_mutant(path, change):
    status, rounds, lpk0 = _load(path), _rounds(), _lpk0()
    rows = status["reviewRounds"]
    if change == "schema":
        status["schemaVersion"] = status["schemaVersion"].replace("/v1", "/v2")
    elif change == "packet":
        status["packet"] = "MET-LIVE-003"
    elif change == "work_item":
        status["workItem"] = "LINUX-PROBE-KIT-001"
    elif change == "candidate":
        status["candidate"] = "c2"
    elif change == "base":
        status["base"] = "b8db30e5dfc4c820b70553cd1439359d73f4573a"
    elif change == "series":
        status["reviewSeries"] = "MET-LIVE-004/packet"
    elif change == "state":
        status["contractState"] = "CONTRACT_CANDIDATE"
    elif change == "combined":
        status["combinedReview"].reverse()
    elif change == "reviewer":
        status["independentReviewer"] = "the author"
    elif change == "native":
        status["nativeAcceptance"] = True
    elif change == "adoption_ruling":
        status["adoption"]["ruling"] = "MON-LPK1-C2-ADOPT"
    elif change == "adoption_commit":
        status["adoption"]["candidateCommit"] = "5c32adc74e493ac38d5864689a523a20cc0c513c"
    elif change == "record_digest":
        rows[0]["recordSha256"] = _flip(rows[0]["recordSha256"])
    elif change == "identity_digest":
        rows[1]["identitySha256"] = _flip(rows[1]["identitySha256"])
    elif change == "verdict":
        rows[0]["verdict"] = "PASS_FOR_ADOPTION"
    elif change == "subject":
        rows[1]["subjectCommit"] = rows[0]["subjectCommit"]
    elif change == "round_base":
        rows[1]["baseCommit"] = rows[1]["subjectCommit"]
    elif change == "round_dropped":
        rows.pop()
    elif change == "round_key_order":
        rows[0] = dict(reversed(list(rows[0].items())))
    elif change == "lpk0_record":
        status["predecessorRecord"]["record"] = "architecture/probe-kit-scope/README.md"
    elif change == "lpk0_digest":
        status["predecessorRecord"]["sha256"] = _flip(status["predecessorRecord"]["sha256"])
    elif change == "extra_key":
        status["merged"] = True
    elif change == "missing_key":
        del status["nonClaims"]
    elif change == "key_order":
        status = dict(reversed(list(status.items())))
    elif change == "rounds_bytes":
        rounds[1] = (rounds[1][0] + b" ", rounds[1][1])
    elif change == "lpk0_bytes":
        lpk0 = lpk0 + b" "
    else:
        status = list(status.items())
    return path, status, rounds, lpk0


@pytest.mark.parametrize("change", STATUS_CHANGES)
@pytest.mark.parametrize("path", ["architecture/admission-semantics-v4/status.json",
                                  "architecture/proxy-profile-v2/status.json"])
def test_each_status_is_closed_and_records_the_adoption(path, change):
    profile.check_status(path, _load(path), _rounds(), _lpk0())
    with pytest.raises(ValueError, match=re.escape("adopted LINUX-PROBE-KIT-ADMISSION status: " + path)):
        profile.check_status(*_status_mutant(path, change))


def test_both_status_records_name_the_same_rounds_and_adoption():
    v4, p2 = _load(profile.V4_STATUS), _load(profile.P2_STATUS)
    assert v4["reviewRounds"] == p2["reviewRounds"] == profile._round_rows(_rounds())
    assert v4["adoption"] == p2["adoption"] == dict(profile.ADOPTION)
    assert profile.ADOPTION["ruling"] == "MON-LPK1-C3-ADOPT" and profile.ADOPTION["candidate"] == "c3"
    assert [row["recordSha256"][:8] for row in v4["reviewRounds"]] == ["3a3d8576", "3f0fc266"]
    assert [row["identitySha256"][:8] for row in v4["reviewRounds"]] == ["a99419fb", "c3ffba5f"]


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
        record["series"] = "MET-LIVE-004/packet"
    elif change == "round":
        record["round"] = 3 - n
    elif change == "round_text":
        record["round"] = str(n)
    elif change == "verdict":
        record["verdict"] = "PASS_FOR_ADOPTION" if n == 1 else "CHANGES_REQUIRED"
    elif change == "subject":
        record["subject"]["commit"] = profile.BASE_COMMIT
    elif change == "brief":
        record["briefSha256"] = _flip(record["briefSha256"])
    elif change == "identity_schema":
        identity["schemaVersion"] = "planeon.review-identity/v1"
    elif change == "identity_path":
        identity["record"]["path"] = profile.REVIEW_RECORDS[2 - n]
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
        return 3, record_raw, identity_raw, brief
    if change.startswith("identity_"):
        return n, record_raw, _encode(identity), brief
    record_out = _encode(record)
    identity["record"]["sha256"] = profile.digest(record_out)
    return n, record_out, _encode(identity), brief


@pytest.mark.parametrize("change", ROUND_CHANGES)
@pytest.mark.parametrize("n", [1, 2])
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


INDEX_CHANGES = ["schema", "packet", "work_item", "series", "base", "proof", "digest", "verdict", "subject", "dropped",
                 "extra", "rounds_bytes", "not_dict"]


def _index_mutant(change):
    index, rounds = _load(profile.SOURCE_INDEX), _rounds()
    rows = index["inTreeRounds"]
    if change == "schema":
        index["schemaVersion"] = "planeon.internal.linux-probe-kit-admission-index/v2"
    elif change == "packet":
        index["packet"] = "MET-LIVE-003"
    elif change == "work_item":
        index["workItem"] = "LINUX-PROBE-KIT-001"
    elif change == "series":
        index["series"] = "MET-LIVE-004/packet"
    elif change == "base":
        index["baseMain"] = "b8db30e5dfc4c820b70553cd1439359d73f4573a"
    elif change == "proof":
        index["designProof"] = "WORK/out/proof.txt"
    elif change == "digest":
        rows[1]["recordSha256"] = _flip(rows[1]["recordSha256"])
    elif change == "verdict":
        rows[1]["verdict"] = "CHANGES_REQUIRED"
    elif change == "subject":
        rows[0]["subjectCommit"] = rows[1]["subjectCommit"]
    elif change == "dropped":
        rows.pop()
    elif change == "extra":
        rows.append(dict(rows[-1], round=3))
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


ORACLE_CHANGES = ["schema", "file_path", "file_digest", "candidate", "decision", "by", "ref", "date", "test_bytes",
                  "not_bytes", "unknown_path", "other_test"]


def _oracle_mutant(path, change):
    identity_raw, test_raw = profile._verified(path), profile._verified(profile.ORACLE_BINDINGS[path])
    identity = json.loads(identity_raw)
    if change == "schema":
        identity["schemaVersion"] = "planeon.oracle-identity/v2"
    elif change == "file_path":
        identity["file"]["path"] = profile.HEAD_TEST
    elif change == "file_digest":
        identity["file"]["sha256"] = _flip(identity["file"]["sha256"])
    elif change == "candidate":
        identity["candidateCommit"] = "e5d958bea181ec49db3e73df5222b1cf690b33de"
    elif change == "decision":
        identity["ruling"]["decision"] = "REWRITE"
    elif change == "by":
        identity["ruling"]["by"] = "OWNER"
    elif change == "ref":
        identity["ruling"]["ref"] = identity["ruling"]["ref"].split("; ")[0]
    elif change == "date":
        identity["ruling"]["date"] = "2026-10-23"
    elif change == "test_bytes":
        return path, identity_raw, test_raw + b"\n"
    elif change == "not_bytes":
        return path, identity_raw.decode("utf-8"), test_raw
    elif change == "unknown_path":
        return profile.SET_DIR + "oracle-identity.json", identity_raw, test_raw
    elif change == "other_test":
        other = [p for p in profile.ORACLE_BINDINGS if p != path][0]
        return path, identity_raw, profile._verified(profile.ORACLE_BINDINGS[other])
    return path, _encode(identity), test_raw


ORACLE_MESSAGE = "an oracle identity binds its oracle test, with ruling KEEP by the lane monitor: "


@pytest.mark.parametrize("change", ORACLE_CHANGES)
@pytest.mark.parametrize("path", ["architecture/linux-probe-kit-admission/oracle-identity-admission-v4.json",
                                  "architecture/linux-probe-kit-admission/oracle-identity-profile-v2.json"])
def test_each_oracle_identity_binds_its_test_with_keep(path, change):
    profile.check_oracle_identity(path, profile._verified(path), profile._verified(profile.ORACLE_BINDINGS[path]))
    with pytest.raises(ValueError, match=re.escape(ORACLE_MESSAGE)):
        profile.check_oracle_identity(*_oracle_mutant(path, change))


def test_the_oracle_identities_name_their_rulings():
    assert profile.ORACLE_RULINGS[profile.V4_ORACLE_IDENTITY]["ref"] == "MON-LPK1-ORACLE-V4-KEEP; MON-LPK1-ORACLE-R2"
    assert profile.ORACLE_RULINGS[profile.P2_ORACLE_IDENTITY]["ref"] == "MON-LPK1-ORACLE-P2-KEEP; MON-LPK1-ORACLE-R2"
    for path, test in profile.ORACLE_BINDINGS.items():
        identity = _load(path)
        assert identity["file"]["path"] == test and identity["candidateCommit"] == profile.ORACLE_COMMIT


# The models over their vectors ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("ops", [[{"op": "move", "path": ["a"]}], [{"op": "set", "path": "a", "value": 1}],
                                 [{"op": "delete", "path": []}], ["set"], [{"path": ["a"], "value": 1}]])
def test_a_vector_operation_is_closed(ops):
    assert profile._apply_ops({"a": [1, {"b": 2}]}, [{"op": "set", "path": ["a", 1, "b"], "value": 3},
                                                      {"op": "delete", "path": ["a", 0]}]) == {"a": [{"b": 3}]}
    with pytest.raises(ValueError, match="closed vector operation"):
        profile._apply_ops({"a": 1}, ops)


ADMISSION_MESSAGE = "the admission vectors replay with every case at its count and no mismatch: "
ADMISSION_CHANGES = ["manifest", "end_to_end_object", "end_to_end_expect", "final_object", "objects", "directory_hash",
                     "claims", "positive", "dropped_case", "result_counts", "result_mismatch", "result_positives"]


def _admission(label):
    v4, v3 = _models()[:2]
    return (v4, _load(profile.V4_VECTORS), profile.V4_COUNTS) if label == "v4" else (
        v3, _load(profile.V3_VECTORS), profile.V3_COUNTS)


def _admission_mutant(label, change):
    model, vectors, counts = _admission(label)
    if change == "manifest":
        vectors["manifest"][0]["expect"] = None
    elif change == "end_to_end_object":
        vectors["endToEnd"][0]["finalObject"]["metadata"]["name"] = "other"
    elif change == "end_to_end_expect":
        vectors["endToEnd"][0]["expect"] = "A2-RESERVED"
    elif change == "final_object":
        row = vectors["finalObject"][0]
        row["expect"] = None if row["expect"] is not None else "A2-RESERVED"
    elif change == "objects":
        vectors["objects"][0]["expect"] = "S99"
    elif change == "directory_hash":
        vectors["directoryHash"][0]["expect"] = "sha256:" + "0" * 64
    elif change == "claims":
        vectors["claims"][0]["expect"] = "C99"
    elif change == "positive":
        vectors["positives"]["Pod"]["metadata"]["name"] = "Bad.Name"
    elif change == "dropped_case":
        vectors["claims"].pop()
    result = profile.replay_admission(model, vectors)
    if change == "result_counts":
        result["cases"]["claims"] += 1
    elif change == "result_mismatch":
        result["mismatches"].append("N01")
    elif change == "result_positives":
        result["positives"] = tuple(reversed(result["positives"]))
    return label, result, counts


@pytest.mark.parametrize("change", ADMISSION_CHANGES)
@pytest.mark.parametrize("label", ["v4", "v3"])
def test_the_admission_vectors_replay_through_their_models(label, change):
    model, vectors, counts = _admission(label)
    result = profile.replay_admission(model, vectors)
    assert result == {"positives": profile.POSITIVES, "cases": dict(counts), "mismatches": []}
    profile.check_admission_replay(label, result, counts)
    with pytest.raises(ValueError, match=re.escape(ADMISSION_MESSAGE + label)):
        profile.check_admission_replay(*_admission_mutant(label, change))


def test_v4_has_141_cases_and_v3_114():
    assert sum(profile.V4_COUNTS.values()) == 141 and sum(profile.V3_COUNTS.values()) == 114
    assert set(profile.V4_COUNTS) == set(profile.V3_COUNTS)


SEALED_MESSAGE = "the sealed v4 A2 file is the model's rendering with the pinned directory hash"
SEALED_CHANGES = ["raw", "rendered", "objects", "hash", "pinned", "not_bytes", "v3_rendering"]


def _sealed():
    v4, v3 = _models()[:2]
    vectors, raw = _load(profile.V4_VECTORS), profile._verified(profile.V4_SEALED)
    sealed = vectors["sealed"]
    return [raw, v4.manifest_file_bytes(sealed), v4.check_a2_objects(json.loads(raw)["items"], sealed),
            v4.manifest_directory_hash({profile.SEALED_NAME: raw}), vectors["pinned"]["manifestDirectoryHash"]]


def _sealed_mutant(change):
    args = _sealed()
    if change == "raw":
        args[0] = args[0] + b" "
    elif change == "rendered":
        args[1] = args[1] + b"x"
    elif change == "objects":
        args[2] = "S01"
    elif change == "hash":
        args[3] = args[3][:-1] + ("0" if args[3][-1] != "0" else "1")
    elif change == "pinned":
        args[4] = "sha256:5aa2cdec0b8dc08c008b887e30b9954ffc46e7d779365f64db1adfd80656f189"
    elif change == "not_bytes":
        args[0] = args[0].decode("utf-8")
    else:
        v3 = _models()[1]
        args[0] = args[1] = v3.manifest_file_bytes(_load(profile.V3_VECTORS)["sealed"])
    return args


@pytest.mark.parametrize("change", SEALED_CHANGES)
def test_the_sealed_a2_file_is_the_rendering_with_the_pinned_hash(change):
    profile.check_sealed(*_sealed())
    assert len(_sealed()[0]) == 8322 and _sealed()[3] == profile.DIRECTORY_HASH
    with pytest.raises(ValueError, match=re.escape(SEALED_MESSAGE)):
        profile.check_sealed(*_sealed_mutant(change))


@pytest.mark.parametrize("semantics", ["POLICY-ADMISSION-SEMANTICS/v4", "POLICY-ADMISSION-SEMANTICS/v2", None])
def test_the_frozen_v3_model_names_its_semantics(semantics):
    profile.check_v3_model(_models()[1].SEMANTICS_V3)
    with pytest.raises(ValueError, match="the frozen admission v3 model names its semantics"):
        profile.check_v3_model(semantics)


PROFILE_MESSAGE = "profile v2's 67 cases replay with no mismatch"
PROFILE_CHANGES = ["negative", "negative_dropped", "cross_profile", "cross_precondition", "cross_v4", "cross_v3",
                   "cross_facts", "positive", "case_counts"]


def _profile_inputs():
    v4, v3, p2 = _models()[:3]
    return p2, v4, v3, _load(profile.P2_VECTORS), _load(profile.P2_SCHEMA), _load(profile.V4_VECTORS), _load(
        profile.V3_VECTORS)


def _profile_mutant(change):
    p2, v4, v3, vectors, schema, v4_vectors, v3_vectors = _profile_inputs()
    counts = vectors["caseCounts"]
    cases = vectors["crossContract"]["cases"]
    if change == "negative":
        vectors["negative"][1]["expect"] = profile.P01_TEXT
    elif change == "negative_dropped":
        vectors["negative"].pop()
    elif change == "cross_profile":
        cases[0]["expect"]["profileV2"] = "P00 the document does not match the closed profile v2 schema"
    elif change == "cross_precondition":
        cases[0]["expect"]["precondition"] = profile.P40_TEXT
    elif change == "cross_v4":
        cases[0]["expect"]["v4"]["Pod"] = "MC33"
    elif change == "cross_v3":
        cases[0]["expect"]["v3"]["Pod"] = "A2 admit"
    elif change == "cross_facts":
        cases[0]["serverFacts"] = {"alwaysPullImages": True}
    elif change == "positive":
        vectors["positive"]["binding"]["validFrom"] = "x"
    else:
        counts = dict(counts, total=68)
    return profile.replay_profile(p2, v4, v3, vectors, schema, v4_vectors, v3_vectors), counts


@pytest.mark.parametrize("change", PROFILE_CHANGES)
def test_profile_v2s_67_cases_replay_through_the_three_models(change):
    p2, v4, v3, vectors, schema, v4_vectors, v3_vectors = _profile_inputs()
    result = profile.replay_profile(p2, v4, v3, vectors, schema, v4_vectors, v3_vectors)
    assert result == {"positive": 1, "negative": 50, "crossContract": 16, "total": 67, "mismatches": []}
    profile.check_profile_replay(result, vectors["caseCounts"])
    with pytest.raises(ValueError, match=re.escape(PROFILE_MESSAGE)):
        profile.check_profile_replay(*_profile_mutant(change))


P01_MESSAGE = "B-L1-1's P01 text is the README's and K01's and K01b's"
P01_CHANGES = ["readme", "k01", "k01b_dropped", "order", "not_bytes"]


def _p01_mutant(change):
    readme, negatives = profile._verified(profile.P2_README), _load(profile.P2_VECTORS)["negative"]
    ids = [row["id"] for row in negatives]
    if change == "readme":
        readme = readme.replace(profile.P01_TEXT.encode("utf-8"), b"P01 a refusal")
    elif change == "k01":
        negatives[ids.index("K01")]["expect"] = "P01 the profile holds a non-data value"
    elif change == "k01b_dropped":
        del negatives[ids.index("K01b")]
    elif change == "order":
        a, b = ids.index("K01"), ids.index("K01b")
        negatives[a], negatives[b] = negatives[b], negatives[a]
    else:
        readme = readme.decode("utf-8")
    return readme, negatives


@pytest.mark.parametrize("change", P01_CHANGES)
def test_b_l1_1s_p01_text_is_the_readmes_and_k01s_and_k01bs(change):
    profile.check_p01(profile._verified(profile.P2_README), _load(profile.P2_VECTORS)["negative"])
    with pytest.raises(ValueError, match=re.escape(P01_MESSAGE)):
        profile.check_p01(*_p01_mutant(change))


def test_the_layers_refusal_texts_are_profile_v2s_own():
    text = _models()[2].TEXT
    assert profile.P01_TEXT == text["P01"] and profile.P40_TEXT == text["P40"] and profile.P99_TEXT == text["P99"]
    assert profile.P01_TEXT.startswith("P01 ") and "any number parsed as a float" in profile.P01_TEXT


def test_the_restated_precondition_is_profile_v2s_own():
    p2 = _models()[2]
    vectors = _load(profile.P2_VECTORS)
    namespace = vectors["crossContract"]["sealedNamespace"]
    documents = [profile._profile_case(vectors["positive"], row) for row in vectors["crossContract"]["cases"]]
    documents += [profile._profile_case(vectors["positive"], row) for row in vectors["negative"]]
    documents += [{}, [], None, {"binding": {}}, {"binding": None}, {"binding": {"namespace": namespace}},
                  {"binding": {"namespace": "x\ud800"}}, {"binding": {"namespace": "other"}, "x": {1, 2}}]
    results = set()
    for document in documents:
        got = profile._precondition(document, namespace)
        assert got == p2.precondition(document, namespace)
        results.add(tuple(got))
    assert results == {(), (profile.P40_TEXT,), (profile.P99_TEXT,), (profile.P01_TEXT,)}


def test_the_profile_v2_schema_verdict_is_jsonschemas_over_the_positive_and_every_negative():
    import importlib.metadata
    import jsonschema
    assert importlib.metadata.version("jsonschema") == "4.24.0"
    p2 = _models()[2]
    vectors, schema = _load(profile.P2_VECTORS), _load(profile.P2_SCHEMA)
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    documents = [("positive", vectors["positive"], [])]
    documents += [(row["id"], profile._profile_case(vectors["positive"], row), [row["expect"]])
                  for row in vectors["negative"]]
    p00 = []
    for label, document, expect in documents:
        walker_valid = p2.schema_error(document, schema) is None
        assert validator.is_valid(document) is walker_valid, label
        if expect and expect[0].startswith("P00 "):
            p00.append(label)
            assert not validator.is_valid(document), label
    assert len(documents) == 51 and len(p00) > 0
    assert validator.is_valid(vectors["positive"])


def test_the_cross_contract_cases_cover_the_readmes_table():
    cross = _load(profile.P2_VECTORS)["crossContract"]
    assert [row["id"] for row in cross["cases"]] == ["X%02d" % n for n in range(1, 17)]
    assert cross["sealedNamespace"] == _load(profile.V4_VECTORS)["sealed"]["namespace"] == "planeon-qual"
    assert cross["cases"][0]["expect"]["v3"]["Pod"] == "MC33" and cross["cases"][0]["expect"]["v4"]["Pod"] == "A2 admit"


# The pins and classes (B-L1-4) -----------------------------------------------------------------------------------------

PINS_MESSAGE = "the mechanics pins record is closed"
PINS_CHANGES = ["schema", "extra_member", "missing_member", "member_order", "unsorted", "duplicate", "row_key", "row_sha",
                "lists_empty", "lists_label", "rule", "counts", "class_rows", "class_two_forms", "class_name",
                "class_source", "class_extra_key", "not_dict"]


def _pins_mutant(change):
    record = _pins()
    pins, rows = record["unchangedPins"], record["evolutionSurfaceClasses"]
    if change == "schema":
        record["schemaVersion"] = "planeon.internal.linux-probe-kit-admission-pins/v2"
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
    elif change == "class_rows":
        rows.pop()
    elif change == "class_two_forms":
        rows[0]["prefix"] = "architecture/"
        del rows[0]["source"]
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
    return row, raw, profile.authority()["changedFiles"].get(row["path"])


@pytest.mark.parametrize("index", range(77))
def test_every_pin_holds_at_this_era(index):
    row, raw, rule = _pin_inputs(_pins()["unchangedPins"][index])
    profile.check_pin(row, raw, rule)
    if row["rule"] == "BYTE_IDENTICAL":
        assert rule is None and profile.digest(raw) == row["sha256"] == profile.ERA_SHA256[row["path"]]
        mutants = [(dict(row, sha256=_flip(row["sha256"])), raw, rule), (row, raw + b" ", rule), (row, None, rule),
                   (row, raw, {"beforeSha256": row["sha256"]}), (dict(row, rule="STEP_RULE"), raw, rule)]
    else:
        assert rule is not None and rule["beforeSha256"] == row["sha256"] and row["path"] not in profile.ERA_SHA256
        mutants = [(row, raw, None), (row, raw, dict(rule, beforeSha256=_flip(rule["beforeSha256"]))),
                   (dict(row, path="architecture/proxy-contract-amendment.json"), raw, rule),
                   (dict(row, sha256=_flip(row["sha256"])), raw, rule), (dict(row, rule="BYTE_IDENTICAL"), raw, rule)]
    for args in mutants:
        with pytest.raises(ValueError, match=re.escape(PIN_MESSAGE)):
            profile.check_pin(*args)


def test_the_pins_are_section_7s_list():
    pins = _pins()["unchangedPins"]
    step = [row["path"] for row in pins if row["rule"] == "STEP_RULE"]
    assert step == sorted(["scripts/validate_admission_channel_v3.py", "tests/test_admission_channel_v3.py",
                           "scripts/validate_compiled_filter_programs_v3.py", "scripts/validate_w03_plan_amend_2.py",
                           "scripts/validate_policy_observation_digests.py", "scripts/validate_i06_backend_profile.py",
                           "scripts/validate_proxy_contract.py"])
    assert len([row for row in pins if "F2.7" in row["lists"]]) == 46
    labels = {label for row in pins for label in row["lists"]}
    assert labels == set(profile.PIN_LISTS)
    paths = {row["path"] for row in pins}
    for path in ("architecture/proxy-contract-inputs/profile.schema.json", "architecture/proxy-contract-inputs/vectors.json",
                 "architecture/proxy-contract-amendment.json", "architecture/proxy-contract-inputs/baseline.json",
                 "architecture/chain-compaction/identity-rule.json", "docs/alpha-2/PROXY_CONTRACT_READINESS.md",
                 "architecture/artifact-edges/operator-harness-engineering-v10.json"):
        assert path in paths


CLASS_MESSAGE = "every evolution-surface class row resolves to its class at this era"
CLASS_CHANGES = ["class", "resolved", "uncovered", "leading_zero", "paths_not_list", "resolved_not_dict"]


def _classes():
    surface, record = _models()[3], _load(profile.SURFACE_RECORD)
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
        rows[0]["path"] = "architecture/linux-probe-kit-admission-authority.yaml"
    elif change == "leading_zero":
        rows.append({"pattern": profile.SET_DIR + "review-round0<n>.json", "class": "REVIEW_RECORD",
                     "source": "DESIGN_REV4_SECTION_2"})
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


def test_the_class_rows_cover_the_review_set_by_form():
    rows, paths, resolved = _classes()
    by_class = {}
    for row in rows:
        for path in profile.class_paths(row, paths):
            by_class.setdefault(row["class"], set()).add(path)
    assert by_class["REVIEW_RECORD"] == set(profile.REVIEW_RECORDS)
    assert by_class["ORACLE_TESTS"] == set(profile.ORACLE_TESTS)
    assert set(profile.REVIEW_IDENTITIES) | {profile.PINS_PATH, profile.PACKET_PATH, profile.AUTHORITY_PATH,
                                             profile.VALIDATOR_PATH, profile.HEAD_TEST} <= by_class["CONTRACT_AND_SOURCE"]
    assert set(profile.CONTRACT_FILES) <= by_class["CONTRACT_AND_SOURCE"]
    assert profile.class_paths({"pattern": profile.SET_DIR + "review-round<n>.json"},
                               [profile.SET_DIR + "review-round01.json", profile.SET_DIR + "review-round1.json",
                                profile.SET_DIR + "review-round.json", profile.SET_DIR + "review-roundx.json"]) == [
        profile.SET_DIR + "review-round1.json"]
    assert len(rows) == profile.CLASS_ROWS == 18


# The registry, the gate list and the gate hits -------------------------------------------------------------------------

REGISTRY_MESSAGE = "the registry is 261's, unchanged, with this packet's PACKET and CONTRACT series pinning their briefs"
REGISTRY_CHANGES = ["registry_bytes", "packet_brief_bytes", "contract_brief_bytes", "not_bytes", "contract_dropped",
                    "packet_kind", "contract_digest", "contract_version", "extra_series"]


def _registry_mutant(change):
    raw, packet, contract = (profile._verified(path) for path in (profile.REGISTRY_PATH, profile.PACKET_BRIEF,
                                                                  profile.CONTRACT_BRIEF))
    if change == "registry_bytes":
        return raw + b" ", packet, contract
    if change == "packet_brief_bytes":
        return raw, packet + b" ", contract
    if change == "contract_brief_bytes":
        return raw, packet, contract + b" "
    if change == "not_bytes":
        return raw.decode("utf-8"), packet, contract
    registry = json.loads(raw)
    entries = [entry for entry in registry["briefs"] if entry["series"].startswith("MET-LIVE-004/")]
    if change == "contract_dropped":
        registry["briefs"].remove(entries[1])
    elif change == "packet_kind":
        entries[0]["kind"] = "CONTRACT"
    elif change == "contract_digest":
        entries[1]["sha256"] = _flip(entries[1]["sha256"])
    elif change == "contract_version":
        entries[1]["version"] = 2
    else:
        registry["briefs"].append(dict(entries[1], series="MET-LIVE-004/design"))
    return (json.dumps(registry, indent=1) + "\n").encode("ascii"), packet, contract


@pytest.mark.parametrize("change", REGISTRY_CHANGES)
def test_the_registry_is_261s_unchanged_with_this_packets_two_series(change):
    raw = profile._verified(profile.REGISTRY_PATH)
    profile.check_registry(raw, profile._verified(profile.PACKET_BRIEF), profile._verified(profile.CONTRACT_BRIEF))
    registry = json.loads(raw)
    assert len(registry["briefs"]) == 8
    assert [row["series"] for row in registry["briefs"] if row["series"].startswith("MET-LIVE-004")] == [
        "MET-LIVE-004/packet", "MET-LIVE-004/contract"]
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
    surface = _models()[3]
    record = _load(profile.SURFACE_RECORD)
    # Data, not gate material: the model's own approvers of the changed files are the lane monitor or the owner.
    assert surface.pr_approvers(record, changed) == ["LANE_MONITOR", "OWNER"]
    for path in profile.ORACLE_TESTS:
        assert surface.resolve(record, path) == "ORACLE_TESTS"
    for path in profile.REVIEW_RECORDS:
        assert surface.resolve(record, path) == "REVIEW_RECORD"
    for path in profile.CONTRACT_FILES + profile.REVIEW_IDENTITIES + (
            profile.SOURCE_INDEX, profile.V4_ORACLE_IDENTITY, profile.P2_ORACLE_IDENTITY, profile.PINS_PATH,
            profile.HEAD_TEST, profile.VALIDATOR_PATH, profile.AUTHORITY_PATH, profile.PACKET_PATH):
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
                      "check_round", "check_source_index", "check_oracle_identity", "_apply_ops",
                      "check_admission_replay", "check_sealed", "check_v3_model", "check_profile_replay", "check_p01",
                      "check_pins_record", "check_pin", "check_classes", "check_registry", "check_gate_list",
                      "check_gate_hits"}
CHECK_TESTS = {
    "MET-LIVE-004 reviewed bytes are bound: ": "test_a_path_outside_the_era_is_refused_before_it_is_read",
    "unreviewed LINUX-PROBE-KIT-ADMISSION source: ": "test_every_era_file_is_bound_by_digest",
    FREEZE: "test_the_freeze_refuses_every_other_change",
    "this packet adds exactly its contract files, review set, oracle tests and layer test, each once":
        "test_the_packet_adds_exactly_its_files_each_once",
    "a file this packet adds is a regular file of git mode 100644: ":
        "test_an_added_file_is_a_regular_file_of_mode_100644_without_a_local_path",
    "no absolute local path in a file this packet adds: ":
        "test_an_added_file_is_a_regular_file_of_mode_100644_without_a_local_path",
    "adopted LINUX-PROBE-KIT-ADMISSION status: ": "test_each_status_is_closed_and_records_the_adoption",
    "a CONTRACT round is bound to its published record and identity: round ":
        "test_each_contract_round_is_bound_to_its_record_and_identity",
    "the source index names this packet's in-tree rounds": "test_the_source_index_names_the_in_tree_rounds",
    ORACLE_MESSAGE: "test_each_oracle_identity_binds_its_test_with_keep",
    "closed vector operation": "test_a_vector_operation_is_closed",
    ADMISSION_MESSAGE: "test_the_admission_vectors_replay_through_their_models",
    SEALED_MESSAGE: "test_the_sealed_a2_file_is_the_rendering_with_the_pinned_hash",
    "the frozen admission v3 model names its semantics": "test_the_frozen_v3_model_names_its_semantics",
    PROFILE_MESSAGE: "test_profile_v2s_67_cases_replay_through_the_three_models",
    P01_MESSAGE: "test_b_l1_1s_p01_text_is_the_readmes_and_k01s_and_k01bs",
    PINS_MESSAGE: "test_the_pins_record_is_closed",
    PIN_MESSAGE: "test_every_pin_holds_at_this_era",
    CLASS_MESSAGE: "test_every_class_row_resolves_to_its_class",
    REGISTRY_MESSAGE: "test_the_registry_is_261s_unchanged_with_this_packets_two_series",
    "the evolution surface record derives 31 exact or prefix gate entries":
        "test_the_gate_list_is_31_exact_or_prefix_entries",
    GATE_MESSAGE: "test_the_packets_changed_files_hold_no_gate_path",
    "unreviewed current source: ": "test_the_canonical_check_reads_this_eras_bytes",
    "canonical byte-minimal inverse hunks: ": "test_whole_line_hunks_are_refused_where_canonical_ones_differ"}
NAMED_MESSAGES = {FREEZE: "FREEZE", ORACLE_MESSAGE: "ORACLE_MESSAGE", ADMISSION_MESSAGE: "ADMISSION_MESSAGE",
                  SEALED_MESSAGE: "SEALED_MESSAGE", PROFILE_MESSAGE: "PROFILE_MESSAGE", P01_MESSAGE: "P01_MESSAGE",
                  PINS_MESSAGE: "PINS_MESSAGE", PIN_MESSAGE: "PIN_MESSAGE", CLASS_MESSAGE: "CLASS_MESSAGE",
                  REGISTRY_MESSAGE: "REGISTRY_MESSAGE", GATE_MESSAGE: "GATE_MESSAGE"}


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
