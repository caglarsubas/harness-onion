"""Exact source lineage for MET-ENFORCE-041; the I01 digest contract and edge record v10: the head keeps the full fan-in (8 own and 69 predecessor routes, every catalog walk and round trip, the full payload loop), and the semantic check (the freeze, the files added, the adoption with its seven reviews and briefs, edge record v10, the model replaying its vectors from this era's bytes, and the canonical hunks) has a failing case for every refusal, each on plain data. C1-1 follows: VPO's validate_messages and VPC's validate_profile on the complete I01 positive, with no skip, expected-failure mark or import guard."""
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

from scripts import validate_policy_observation_digests as profile
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
    # The newer MET-GOV-002 layer is projected away before this layer's payload checks.
    return profile.successor.historical_catalog(packets())


def changed_test():
    return next(path for path in profile._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert profile.validate() is None
    current = packets()
    accepted = profile.historical_catalog(current)
    assert len(current) == 259 and len(accepted) == 257
    assert set(accepted) == set(current) - {profile.NEW_PACKET, profile.successor.NEW_PACKET}
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


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "evs_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = profile.historical_bytes(path, raw) if route in ("current_test", "old_bytes") else None
    current_packets = packets() if route == "catalog" else None
    layer = layer_packets() if route == "payloads" else None
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
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
    with pytest.raises(ValueError, match="policy observation digests history authority digest"):
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
    assert len(profile.historical_catalog(current)) == 257


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
    assert len(profile.historical_catalog(current)) == 257
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
    assert len(rules) == 258 and len(parsed) == 257
    assert profile._packet_rules() is rules and len(parsed) == 257
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
    with pytest.raises(ValueError, match="policy observation digests history authority digest"):
        profile.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = layer_packets()
    profile.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "policy-observation-digests-authority.json").write_bytes(
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
    # The newer MET-GOV-002 layer refuses a mutated validator before this layer.
    with pytest.raises(ValueError, match="unreviewed current source: scripts/validate_policy_observation_digests.py"):
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
            assert all("validate_" not in alias.name or alias.name == "validate_review_record"
                       for alias in node.names)


def _count_authority_reads(monkeypatch):
    counts = {}
    for module in (profile.successor, profile, evs, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner):
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
    expected = {module.__name__: 1 for module in (profile.successor, profile, evs, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner)}
    if route == "current_test":
        # The forward route reads this layer's newest bytes and then projects them forward once more.
        assert all(counts[name] >= 1 for name in expected) and set(counts) == set(expected)
    else:
        assert counts == expected


# MET-ENFORCE-041 (DIGEST-CONTRACT): this era's check, and a failing case for every check. Every mutant below is applied
# to plain data handed to the layer's pure checks: nothing in the layer or the library is patched or swapped. The
# mutants are built by the pure helpers _<area>_mutant(change), one change name per mutant.

VALIDATE = profile.validate_policy_observation_digests
# Tamper values name packets, bases and files that already exist and that this record does not carry in the tampered
# place (edge record v8's packet, 253's merge, the I01 wire's validator), never a later packet id, so that no later
# packet's mechanics can turn a negative into a positive (the monitor's slot-253 catch).
OTHER_PACKET = "MET-ENFORCE-039"
OTHER_BASE = "585364b94e3e4a8bf1418ef750ce3d71cd38f95a"
OTHER_PATH = "scripts/validate_policy_observation.py"
OTHER_SHA256 = "0" * 64


def _load(path):
    return json.loads(profile.reviewed_bytes(path))


def _status():
    return _load(profile.STATUS_PATH)


def _records():
    return [_load(path) for path in profile.RECORDS]


def _flip(text):
    """A different lowercase hex digest of the same length."""
    return text[:-1] + ("0" if text[-1] != "0" else "1")


def test_the_contract_holds_for_this_era():
    assert VALIDATE() is None


def test_every_added_file_record_and_brief_is_pinned():
    pinned = set(profile.ERA_SHA256)
    assert len(profile.NEW_FILES) == 21 and len(set(profile.NEW_FILES)) == 21
    assert len(profile.FROZEN_PATHS) == 30 and len(set(profile.FROZEN_PATHS)) == 30
    assert pinned == set(profile.NEW_FILES) | set(profile.FROZEN_PATHS) and len(pinned) == 51
    assert len(profile.RECORDS) == len(profile.BRIEFS) == 7 and len(profile.DIRECTORY_FILES) == 18
    assert all(path.startswith(profile.CONTRACT_DIR + "/") for path in profile.DIRECTORY_FILES)
    assert [row["record"] for row in _status()["reviews"]] == list(profile.RECORDS)
    assert [row["brief"] for row in _status()["reviews"]] == list(profile.BRIEFS)
    assert profile.MODEL_FILES == profile.FROZEN_INPUTS + profile.FROZEN_MODELS
    for path, expected in profile.ERA_SHA256.items():
        assert profile.digest(profile.reviewed_bytes(path)) == expected


@pytest.mark.parametrize("path", sorted(profile.ERA_SHA256))
def test_every_era_file_is_bound_by_digest(path):
    raw = profile._verified(path)
    assert profile._era_bytes(path, raw) == raw
    for changed in (raw + b" ", bytearray(raw)):
        with pytest.raises(ValueError, match=re.escape("unreviewed DIGEST-CONTRACT source: " + path)):
            profile._era_bytes(path, changed)


def test_a_path_outside_the_era_is_refused_before_it_is_read():
    for path in (profile.CONTRACT_DIR + "/notes.md", profile.DESIGN_DIR + "/review-round4.json", OTHER_PATH,
                 profile.VALIDATOR_PATH, "tests/test_policy_observation_digests.py", None):
        with pytest.raises(ValueError, match="MET-ENFORCE-041 reviewed bytes are bound: "):
            profile._verified(path)
        with pytest.raises(ValueError, match="MET-ENFORCE-041 reviewed bytes are bound: "):
            profile._era_bytes(path, b"")


# The freeze and the files this packet adds -----------------------------------------------------------------------------

FREEZE = ("no earlier contract, record, frozen model or edge record changes, and under architecture/ only the "
          "contract's directory and edge record v10 with its README are added: ")
FREEZE_CASES = [("architecture/policy-observation-inputs/vectors.json", "changed"), (profile.V9_EDGE, "changed"),
                ("architecture/edge-record-v9/status.json", "changed"), (profile.MODEL_PATH, "changed"),
                ("scripts/i06_backend_profile_v4.py", "changed"), ("docs/alpha-2/POLICY_OBSERVATION_READINESS.md", "changed"),
                (profile.EDGES_DIR + "README-v11.md", "added"), (profile.PPV_PATH, "added"),
                ("architecture/proxy-contract-inputs/profile.schema.json", "added"),
                ("architecture/i06-backend-profile/identity-closure.json", "added")]


def _changed_and_added():
    return list(profile._PROJECTION_RULES), list(profile.authority()["newFiles"])


@pytest.mark.parametrize("path, where", FREEZE_CASES)
def test_no_earlier_contract_record_frozen_model_or_edge_record_changes(path, where):
    changed, added = _changed_and_added()
    profile.check_freeze(changed, added)
    with pytest.raises(ValueError, match=re.escape(FREEZE + path)):
        profile.check_freeze(changed + ([path] if where == "changed" else []),
                             added + ([path] if where == "added" else []))


NEW_FILE_CHANGES = ["missing", "extra", "changed", "model_missing", "edge_missing", "brief_missing"]


def _new_files_mutant(change):
    changed, added = _changed_and_added()
    if change == "missing":
        added.remove(profile.STATUS_PATH)
    elif change == "extra":
        added.append(profile.CONTRACT_DIR + "/review-round5.json")
    elif change == "changed":
        changed.append(profile.RECORDS[0])
    elif change == "model_missing":
        added.remove(profile.MODEL_PATH)
    elif change == "edge_missing":
        added.remove(profile.V10_README)
    else:
        added.remove(profile.BRIEFS[3])
    return added, changed


@pytest.mark.parametrize("change", NEW_FILE_CHANGES)
def test_the_contract_files_records_briefs_model_and_edge_record_are_new_each_once(change):
    changed, added = _changed_and_added()
    profile.check_new_files(added, changed)
    with pytest.raises(ValueError, match="the contract's files, records and briefs, the model and edge record v10 are "
                                         "new in this packet, each once"):
        profile.check_new_files(*_new_files_mutant(change))


TREE_HOLDS = "the contract directory holds exactly its files and its design folder, each file of mode 100644"
TREE_CHANGES = [("extra", TREE_HOLDS), ("missing", TREE_HOLDS), ("executable", TREE_HOLDS), ("link", TREE_HOLDS),
                ("design_extra", TREE_HOLDS), ("design_link", TREE_HOLDS),
                ("directory_link", "the contract directory is a directory, not a link")]


def _tree_mutant(change):
    mode, tree = profile.reviewed_mode(profile.CONTRACT_DIR), dict(profile.reviewed_tree(profile.CONTRACT_DIR))
    if change == "extra":
        tree[profile.CONTRACT_DIR + "/notes.md"] = stat.S_IFREG | 0o644
    elif change == "missing":
        del tree[profile.RECORDS[4]]
    elif change == "executable":
        tree[profile.STATUS_PATH] = stat.S_IFREG | 0o755
    elif change == "link":
        tree[profile.BRIEFS[0]] = stat.S_IFLNK | 0o777
    elif change == "design_extra":
        tree[profile.DESIGN_DIR + "/review-round4.json"] = stat.S_IFREG | 0o644
    elif change == "design_link":
        tree[profile.DESIGN_DIR] = stat.S_IFLNK | 0o777
    else:
        mode = stat.S_IFLNK | 0o777
    return mode, tree


@pytest.mark.parametrize("change, message", TREE_CHANGES)
def test_the_contract_directory_is_closed_and_every_file_is_mode_100644(change, message):
    mode, tree = profile.reviewed_mode(profile.CONTRACT_DIR), profile.reviewed_tree(profile.CONTRACT_DIR)
    assert sorted(tree) == sorted(profile.DIRECTORY_FILES + (profile.DESIGN_DIR,)) and stat.S_ISDIR(mode)
    profile.check_contract_tree(mode, tree)
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.check_contract_tree(*_tree_mutant(change))


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
    # A list of the scanned-for patterns names no path.
    profile.check_added_file(path, mode, raw + b" /" + b"users/, /" + b"private/, .local" + b"/state, email pattern")


# The adoption -------------------------------------------------------------------------------------------------------

STATUS_CHANGES = ["schema", "work_item", "packet", "slot", "slot_type", "state", "base", "reviewers", "subject_value",
                  "subject_order", "builder", "builder_order", "non_claim", "extra_key", "missing_key", "key_order"]


def _status_mutant(change):
    status = _status()
    if change == "schema":
        status["schemaVersion"] = "planeon.internal.edge-record-v9-status/v1"
    elif change == "work_item":
        status["workItem"] = "EDGE-V9"
    elif change == "packet":
        status["packet"] = OTHER_PACKET
    elif change == "slot":
        status["slot"] = 256
    elif change == "slot_type":
        status["slot"] = 258.0
    elif change == "state":
        status["status"] = "CONTRACT_CANDIDATE"
    elif change == "base":
        status["baseMain"] = OTHER_BASE
    elif change == "reviewers":
        status["independentReviewers"] = "SEPARATE_AGENT_NOT_AUTHOR"
    elif change == "subject_value":
        status["adoptedSubject"][profile.MODEL_PATH] = OTHER_SHA256
    elif change == "subject_order":
        status["adoptedSubject"] = dict(reversed(list(status["adoptedSubject"].items())))
    elif change == "builder":
        status["builder"]["sha256"]["c4"] = status["builder"]["sha256"]["c3"]
    elif change == "builder_order":
        status["builder"] = dict(reversed(list(status["builder"].items())))
    elif change == "non_claim":
        status["nonClaims"].pop()
    elif change == "extra_key":
        status["rounds"] = []
    elif change == "missing_key":
        del status["slips"]
    else:
        status["packet"] = status.pop("packet")
    return status


@pytest.mark.parametrize("change", STATUS_CHANGES)
def test_the_status_is_closed_and_records_the_adoption(change):
    profile.check_status(_status())
    with pytest.raises(ValueError, match="adopted DIGEST-CONTRACT status"):
        profile.check_status(_status_mutant(change))


ADOPTION_CHANGES = ["decision", "decided_by", "date", "condition", "readoption", "superseded", "extra_key",
                    "missing_key", "key_order", "not_a_mapping"]


def _adoption_mutant(change):
    adoption = _status()["adoption"]
    if change == "decision":
        adoption["decision"] = adoption["decision"].replace("without asking me again", "")
    elif change == "decided_by":
        adoption["decidedBy"] = "the owner"
    elif change == "date":
        adoption["date"] = "2026-10-21"
    elif change == "condition":
        adoption["condition"] = "contract review round 2 clean (NOTE findings only)"
    elif change == "readoption":
        adoption["readoption"] = adoption["readoption"].replace("871d582b", "a379363c")
    elif change == "superseded":
        adoption["supersededAdoption"] = adoption["supersededAdoption"].replace("candidate 3", "candidate 2")
    elif change == "extra_key":
        adoption["note"] = "x"
    elif change == "missing_key":
        del adoption["condition"]
    elif change == "key_order":
        adoption["date"] = adoption.pop("date")
    else:
        adoption = [adoption]
    return adoption


@pytest.mark.parametrize("change", ADOPTION_CHANGES)
def test_the_adoption_is_the_monitors_decision_verbatim(change):
    profile.check_adoption(_status()["adoption"])
    with pytest.raises(ValueError, match="the adoption is the lane monitor's decision, verbatim"):
        profile.check_adoption(_adoption_mutant(change))


@pytest.mark.parametrize("path", profile.SUBJECT)
def test_the_contract_files_are_the_adopted_bytes(path):
    raw = profile._verified(path)
    profile.check_subject(path, raw)
    for args in ((path, raw + b" "), (path, bytearray(raw)), (OTHER_PATH, raw)):
        with pytest.raises(ValueError, match=re.escape("the contract files are the adopted candidate 4: ")):
            profile.check_subject(*args)


REVIEWS_CHANGES = ["reordered", "dropped", "design_verdict", "last_verdict", "last_subject", "last_severities",
                   "last_files", "not_a_list"]


def _reviews_mutant(change):
    reviews, last = _status()["reviews"], _records()[-1]
    if change == "reordered":
        reviews[3], reviews[4] = reviews[4], reviews[3]
    elif change == "dropped":
        reviews.pop(0)
    elif change == "design_verdict":
        reviews[2]["verdict"] = "PASS_FOR_ADOPTION"
    elif change == "last_verdict":
        reviews[-1]["verdict"] = "CHANGES_REQUIRED"
    elif change == "last_subject":
        reviews[-1]["subject"] = "candidate 3"
    elif change == "last_severities":
        reviews[-1]["severities"] = {"MINOR": 1, "NOTE": 1}
    elif change == "last_files":
        last["subject"]["files"][profile.VECTORS_PATH] = OTHER_SHA256
    else:
        reviews = tuple(reviews)
    return reviews, last


@pytest.mark.parametrize("change", REVIEWS_CHANGES)
def test_seven_reviews_in_order_and_the_last_passed_with_notes_only(change):
    profile.check_reviews(_status()["reviews"], _records()[-1])
    with pytest.raises(ValueError, match="seven reviews in order; the last passed with NOTEs only on the adopted "
                                         "candidate 4"):
        profile.check_reviews(*_reviews_mutant(change))


REVIEW_CHANGES = ["record_bytes", "record_digest", "record_path", "row_review", "row_verdict", "row_base", "row_subject",
                  "row_brief", "row_brief_digest", "row_findings", "row_severities", "severity_order", "row_key_order",
                  "record_verdict", "record_reviewer", "record_brief", "record_subject", "record_finding",
                  "record_key_order"]


def _review_mutant(number, change):
    row, raw = _status()["reviews"][number - 1], profile._verified(profile.RECORDS[number - 1])
    record = json.loads(raw)
    if change == "record_bytes":
        raw = raw + b" "
    elif change == "record_digest":
        row["recordSha256"] = _flip(row["recordSha256"])
    elif change == "record_path":
        row["record"] = profile.RECORDS[number % len(profile.RECORDS)]
    elif change == "row_review":
        row["review"] = "contract round 5"
    elif change == "row_verdict":
        row["verdict"] = "PASS_FOR_ADOPTION" if row["verdict"] != "PASS_FOR_ADOPTION" else "CHANGES_REQUIRED"
    elif change == "row_base":
        row["base"] = OTHER_BASE
    elif change == "row_subject":
        row["subject"] = "candidate 9" if type(row["subject"]) is str else {"DESIGN.md rev 9": OTHER_SHA256}
    elif change == "row_brief":
        row["brief"] = profile.BRIEFS[number % len(profile.BRIEFS)]
    elif change == "row_brief_digest":
        row["briefSha256"] = _flip(row["briefSha256"])
    elif change == "row_findings":
        row["findings"] = row["findings"][1:]
    elif change == "row_severities":
        row["severities"] = dict(row["severities"], NOTE=row["severities"].get("NOTE", 0) + 1)
    elif change == "severity_order":
        row["severities"] = (dict(reversed(list(row["severities"].items()))) if len(row["severities"]) > 1
                             else dict(row["severities"], MAJOR=0))
    elif change == "row_key_order":
        row["verdict"] = row.pop("verdict")
    elif change == "record_verdict":
        record["verdict"] = "PASS_FOR_CONTRACT" if record["verdict"] != "PASS_FOR_CONTRACT" else "CHANGES_REQUIRED"
    elif change == "record_reviewer":
        record["reviewer"] = "the author"
    elif change == "record_brief":
        record["brief"]["sha256"] = _flip(record["brief"]["sha256"])
    elif change == "record_subject":
        if "candidate" in record["subject"]:
            record["subject"]["candidate"] = record["subject"]["candidate"] + 1
        else:
            record["subject"]["sha256"] = OTHER_SHA256
    elif change == "record_finding":
        record["findings"][0]["id"] = "X-1"
    else:
        record["verdict"] = record.pop("verdict")
    return number, row, record, raw


@pytest.mark.parametrize("number", [1, 2, 3, 4, 5, 6, 7])
@pytest.mark.parametrize("change", REVIEW_CHANGES)
def test_each_review_is_bound_to_its_record_and_its_subject(number, change):
    raw = profile._verified(profile.RECORDS[number - 1])
    profile.check_review(number, _status()["reviews"][number - 1], json.loads(raw), raw)
    with pytest.raises(ValueError, match="review %d is bound to its record and its subject" % number):
        profile.check_review(*_review_mutant(number, change))


REDACTION_CHANGES = ["brief_path", "reviewed_digest", "published_digest", "published_bytes", "substitution_count",
                     "substitution_to", "substitution_order", "substitution_key_order", "key_order", "dropped", "extra"]


def _briefs():
    return {path: profile._verified(path) for path in profile.BRIEFS}


def _redaction_mutant(change):
    status, briefs = _status(), _briefs()
    rows = status["briefRedactions"]
    if change == "brief_path":
        rows[0]["brief"] = profile.BRIEFS[1]
    elif change == "reviewed_digest":
        rows[1]["reviewedSha256"] = _flip(rows[1]["reviewedSha256"])
    elif change == "published_digest":
        rows[2]["publishedSha256"] = _flip(rows[2]["publishedSha256"])
    elif change == "published_bytes":
        briefs[profile.BRIEFS[3]] = briefs[profile.BRIEFS[3]] + b" "
    elif change == "substitution_count":
        rows[4]["substitutions"][0]["count"] += 1
    elif change == "substitution_to":
        rows[5]["substitutions"][1]["to"] = "<tmp>/"
    elif change == "substitution_order":
        rows[6]["substitutions"].reverse()
    elif change == "substitution_key_order":
        rows[0]["substitutions"][0]["count"] = rows[0]["substitutions"][0].pop("count")
        rows[0]["substitutions"][0]["to"] = rows[0]["substitutions"][0].pop("to")
    elif change == "key_order":
        rows[1]["brief"] = rows[1].pop("brief")
    elif change == "dropped":
        rows.pop()
    else:
        rows.append(dict(rows[0]))
    return status, briefs


@pytest.mark.parametrize("change", REDACTION_CHANGES)
def test_each_published_brief_is_the_redacted_copy_its_review_names(change):
    profile.check_redactions(_status(), _briefs())
    with pytest.raises(ValueError, match="each published brief is the redacted copy its review names, by digest"):
        profile.check_redactions(*_redaction_mutant(change))


CARRIED_CHANGES = ["item", "to", "action_empty", "c1_action", "c1_moved", "dropped", "extra", "key_order"]


def _carried_mutant(change):
    status = _status()
    carried = status["carried"]
    if change == "item":
        carried[1]["item"] = carried[1]["item"].replace("D3-1", "D3-2")
    elif change == "to":
        carried[0]["to"] = "HE-004-I01B (R10)"
    elif change == "action_empty":
        carried[2]["action"] = " "
    elif change == "c1_action":
        carried[0]["action"] = carried[0]["action"].replace("with no skip, ", "")
    elif change == "c1_moved":
        carried[0], carried[1] = carried[1], carried[0]
    elif change == "dropped":
        carried.pop()
    elif change == "extra":
        carried.append(dict(carried[0]))
    else:
        carried[0]["item"] = carried[0].pop("item")
    return status


@pytest.mark.parametrize("change", CARRIED_CHANGES)
def test_the_carried_items_are_present_c1_1_first(change):
    profile.check_carried(_status())
    with pytest.raises(ValueError, match="the carried items are present, C1-1 first and carried to this packet's layer "
                                         "test"):
        profile.check_carried(_carried_mutant(change))


SLIP_CHANGES = ["id", "ruling", "what_empty", "dropped", "extra", "key_order"]


def _slips_mutant(change):
    status = _status()
    slips = status["slips"]
    if change == "id":
        slips[2]["id"] = "MON-DIG-BUILD-OTHER"
    elif change == "ruling":
        slips[0]["ruling"] = slips[0]["ruling"].replace("KEEP", "REVERT")
    elif change == "what_empty":
        slips[1]["what"] = ""
    elif change == "dropped":
        slips.pop(2)
    elif change == "extra":
        slips.append(dict(slips[0]))
    else:
        slips[0]["id"] = slips[0].pop("id")
    return status


@pytest.mark.parametrize("change", SLIP_CHANGES)
def test_the_slips_are_present_each_with_its_ruling(change):
    profile.check_slips(_status())
    with pytest.raises(ValueError, match="the slips are present, each with its ruling"):
        profile.check_slips(_slips_mutant(change))


# Edge record v10 ----------------------------------------------------------------------------------------------------

EDGE_KEEPS = ("edge record v10 supersedes v9 by its digest and packet and keeps v9's decision, rules, exclusions, "
              "statuses and key order")
EDGE_ROWS = "edge record v10 carries v9's 68 rows exactly and in order"
EDGE_CHANGES = [("v9_bytes", EDGE_KEEPS), ("key_order", EDGE_KEEPS), ("schema", EDGE_KEEPS), ("rules", EDGE_KEEPS),
                ("statuses", EDGE_KEEPS), ("owner_decision", EDGE_KEEPS), ("supersedes_sha", EDGE_KEEPS),
                ("supersedes_packet", EDGE_KEEPS), ("supersedes_path", EDGE_KEEPS), ("supersedes_order", EDGE_KEEPS),
                ("artifact", EDGE_KEEPS), ("decision_label", EDGE_KEEPS), ("decision_dropped", EDGE_KEEPS),
                ("decision_unquoted", EDGE_KEEPS), ("notes_empty", EDGE_KEEPS), ("row_changed", EDGE_ROWS),
                ("row_reordered", EDGE_ROWS), ("row_dropped", EDGE_ROWS), ("row_extra", EDGE_ROWS),
                ("row_key_order", EDGE_ROWS)]


def _edge():
    v9_raw = profile._verified(profile.V9_EDGE)
    return json.loads(v9_raw), _load(profile.V10_EDGE), v9_raw


def _edge_mutant(change):
    v9, v10, v9_raw = _edge()
    if change == "v9_bytes":
        v9_raw = v9_raw + b" "
    elif change == "key_order":
        v10["notes"] = v10.pop("notes")
        v10["artifacts"] = v10.pop("artifacts")
    elif change == "schema":
        v10["schemaVersion"] = "planeon.internal.artifact-edge-registry/v3"
    elif change == "rules":
        v10["rules"] = v10["rules"][1:]
    elif change == "statuses":
        v10["statuses"] = dict(v10["statuses"], EXTRA="x") if type(v10["statuses"]) is dict else v10["statuses"][1:]
    elif change == "owner_decision":
        v10["ownerDecision"] = v10["ownerDecisions"][0]
    elif change == "supersedes_sha":
        v10["supersedes"]["sha256"] = "sha256:" + OTHER_SHA256
    elif change == "supersedes_packet":
        v10["supersedes"]["packet"] = OTHER_PACKET
    elif change == "supersedes_path":
        v10["supersedes"]["path"] = profile.EDGES_DIR + "operator-harness-engineering-v8.json"
    elif change == "supersedes_order":
        v10["supersedes"] = dict(reversed(list(v10["supersedes"].items())))
    elif change == "artifact":
        v10["artifact"] = "policy-observation-i01-wire"
    elif change == "decision_label":
        v10["ownerDecisions"][2] = v10["ownerDecisions"][2].replace("Slot", "Slot 258", 1)
    elif change == "decision_dropped":
        v10["ownerDecisions"].pop()
    elif change == "decision_unquoted":
        v10["ownerDecisions"][1] = v10["ownerDecisions"][1][:-1]
    elif change == "notes_empty":
        v10["notes"] = []
    elif change == "row_changed":
        v10["artifacts"][5]["sha256"] = OTHER_SHA256
    elif change == "row_reordered":
        v10["artifacts"][0], v10["artifacts"][1] = v10["artifacts"][1], v10["artifacts"][0]
    elif change == "row_dropped":
        v10["artifacts"].pop(10)
    elif change == "row_extra":
        v10["artifacts"].append(dict(v10["artifacts"][-1]))
    else:
        v10["artifacts"][3]["mode"] = v10["artifacts"][3].pop("mode")
    return v9, v10, v9_raw


@pytest.mark.parametrize("change, message", EDGE_CHANGES)
def test_edge_record_v10_supersedes_v9_and_carries_its_68_rows(change, message):
    profile.check_edge_record(*_edge())
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.check_edge_record(*_edge_mutant(change))


ROW_CHANGES = ["sha", "bytes", "mode_text", "mode_bits", "commit", "consumer", "consumer_packet", "relation", "status",
               "provider_packet", "provider_path", "key_order"]


def _row_args(number):
    _, v10, _ = _edge()
    spec = profile.NEW_ROWS[number - 69]
    return number, v10["artifacts"][number - 1], spec, profile._verified(spec[0]), profile.reviewed_mode(spec[0])


def _row_mutant(number, change):
    number, row, spec, raw, mode = _row_args(number)
    if change == "sha":
        row["sha256"] = _flip(row["sha256"])
    elif change == "bytes":
        raw = raw + b"\n"
    elif change == "mode_text":
        row["mode"] = "100755"
    elif change == "mode_bits":
        mode = stat.S_IFREG | 0o755
    elif change == "commit":
        row["providerCommit"] = profile.PPV_COMMIT if spec[1] is None else None
    elif change == "consumer":
        row["consumerPath"] = row["consumerPath"].replace("contracts/", "contracts/v2/")
    elif change == "consumer_packet":
        row["consumerPacket"] = "HE-004-I01"
    elif change == "relation":
        row["relation"] = "DERIVED"
    elif change == "status":
        row["status"] = "VENDORED"
    elif change == "provider_packet":
        if spec[3] is None:
            row["providerPacket"] = profile.NEW_PACKET
        else:
            row["providerPacket"] = OTHER_PACKET
    elif change == "provider_path":
        row["providerPath"] = profile.NEW_ROWS[(number - 68) % 4][0]
    else:
        row["sha256"] = row.pop("sha256")
    return number, row, spec, raw, mode


@pytest.mark.parametrize("number", [69, 70, 71, 72])
@pytest.mark.parametrize("change", ROW_CHANGES)
def test_each_new_row_registers_its_providers_exact_bytes_and_mode_before_use(number, change):
    profile.check_new_row(*_row_args(number))
    with pytest.raises(ValueError, match=re.escape("edge record v10 row %d registers its provider's exact bytes and "
                                                   "mode before use: " % number)):
        profile.check_new_row(*_row_mutant(number, change))


ONCE_CHANGES = ["provider", "consumer", "consumer_of_v9"]


def _once_mutant(change):
    v9, v10, _ = _edge()
    if change == "provider":
        v10["artifacts"][70]["providerPath"] = v10["artifacts"][0]["providerPath"]
    elif change == "consumer":
        v10["artifacts"][69]["consumerPath"] = v10["artifacts"][68]["consumerPath"]
    else:
        v10["artifacts"][71]["consumerPath"] = v9["artifacts"][67]["consumerPath"]
    return v9, v10


@pytest.mark.parametrize("change", ONCE_CHANGES)
def test_each_provider_and_new_consumer_is_registered_once(change):
    v9, v10, _ = _edge()
    profile.check_registered_once(v9, v10)
    with pytest.raises(ValueError, match="each provider path, and each new consumer path, is registered once"):
        profile.check_registered_once(*_once_mutant(change))


# The model replays its vectors ---------------------------------------------------------------------------------------

def _model_files():
    return {path: profile._verified(path) for path in profile.MODEL_FILES}


def test_the_model_runs_this_eras_frozen_models():
    models = profile.era_models()
    model, i06v4, i06v3, i06v1, np4 = models
    profile.check_era_models(models)
    assert model.__name__ == "_met_enforce_041_policy_observation_digests"
    assert model.__file__ == str(profile.ROOT / profile.MODEL_PATH)
    assert model.i06v4 is i06v4 and i06v4.v1 is i06v1 and i06v4.v3 is i06v3 and i06v3.w02a is np4
    other = profile.era_models()
    assert other[0] is not model and other[1] is not i06v4
    for mixed in ((model,) + other[1:], models[:3] + (other[3],) + models[4:], models[:4] + (other[4],),
                  models[:2] + (other[2],) + models[3:], models[:4], list(models)):
        with pytest.raises(ValueError, match="the model runs this era's frozen models: I06 v4 with I06 v1 and v3"):
            profile.check_era_models(mixed)


VECTOR_CHANGES = ["helper", "projection_digest", "enforcement_digest", "observation", "complete", "contract_pin",
                  "frozen_model", "frozen_input", "missing_file", "closed_document"]


def _vector_mutant(change):
    vectors, files = _load(profile.VECTORS_PATH), _model_files()
    if change == "helper":
        vectors["helpers"][0]["expect"] = vectors["helpers"][0]["expect"] + "00"
    elif change == "projection_digest":
        row = next(row for row in vectors["vectors"] for want in row["expect"].get("projections", {}).values()
                   if "digest" in want)
        want = next(want for want in row["expect"]["projections"].values() if "digest" in want)
        want["digest"] = "sha256:" + OTHER_SHA256
    elif change == "enforcement_digest":
        row = next(row for row in vectors["vectors"] for want in row["expect"].get("enforcement", {}).values()
                   if "digest" in want)
        want = next(want for want in row["expect"]["enforcement"].values() if "digest" in want)
        want["digest"] = "sha256:" + OTHER_SHA256
    elif change == "observation":
        row = next(row for row in vectors["vectors"] if "observation" in row["expect"])
        row["expect"]["observation"] = row["expect"]["observation"] + ["an unpinned refusal"]
    elif change == "complete":
        vectors["complete"]["binding"]["profileDigest"] = "sha256:" + OTHER_SHA256
    elif change == "contract_pin":
        vectors["contract"]["canonicalSha256"] = OTHER_SHA256
    elif change == "frozen_model":
        files[profile.V4_MODEL] = files[profile.V4_MODEL] + b"\n"
    elif change == "frozen_input":
        files[profile.FROZEN_INPUTS[0]] = files[profile.FROZEN_INPUTS[0]] + b"\n"
    elif change == "missing_file":
        del files[profile.ADM_MODEL]
    else:
        vectors["extra"] = []
    return vectors, files


def test_the_model_replays_its_vectors_with_no_error():
    model = profile.era_models()[0]
    profile.check_vector_replay(model, _load(profile.VECTORS_PATH), _model_files())
    assert model.check_vectors(_load(profile.VECTORS_PATH), _model_files()) == profile.VECTOR_CHECKS == 320


@pytest.mark.parametrize("change", VECTOR_CHANGES)
def test_a_changed_vector_or_frozen_file_fails_the_replay(change):
    model = profile.era_models()[0]
    with pytest.raises(ValueError, match="the model replays its vectors over this era's frozen files with no error"):
        profile.check_vector_replay(model, *_vector_mutant(change))


DEFINITIONS_CHANGES = ["member", "pin", "path", "bytes"]


def _definitions_mutant(change):
    vectors, raw = _load(profile.VECTORS_PATH), profile._verified(profile.DEFINITIONS_PATH)
    if change == "member":
        value = json.loads(raw)
        value["unpinned"] = True
        raw = json.dumps(value).encode("utf-8")
    elif change == "pin":
        vectors["contract"]["canonicalSha256"] = OTHER_SHA256
    elif change == "path":
        vectors["contract"]["path"] = profile.README_PATH
    else:
        raw = raw.replace(b"{", b"[", 1)
    return vectors, raw


@pytest.mark.parametrize("change", DEFINITIONS_CHANGES)
def test_definitions_json_is_the_models_definitions_by_the_vectors_pin(change):
    vectors, raw = _load(profile.VECTORS_PATH), profile._verified(profile.DEFINITIONS_PATH)
    profile.check_definitions(vectors, raw)
    with pytest.raises(ValueError, match="definitions.json is the model's definitions, by the vectors' canonical pin"):
        profile.check_definitions(*_definitions_mutant(change))


def test_the_restated_values():
    status = _status()
    assert profile.ADOPTION == status["adoption"] and profile.ADOPTION_QUOTE == status["adoption"]["decision"]
    assert dict(profile.ADOPTED_SHA256) == status["adoptedSubject"] and profile.BUILDER == status["builder"]
    assert [row[0] for row in profile.REVIEWS] == [row["review"] for row in status["reviews"]]
    assert list(profile.CARRIED) == [(row["item"], row["to"]) for row in status["carried"]]
    assert list(profile.SLIPS) == [(row["id"], row["ruling"]) for row in status["slips"]]
    assert profile.PPV_COMMIT.startswith("33de300c") and profile.EDGE_V9_SHA256.startswith("197f30e4")
    assert profile.BASE_COMMIT == status["baseMain"] and profile.SLOT == status["slot"] == 258
    assert [row[0] for row in profile.NEW_ROWS] == [row["providerPath"] for row in _load(profile.V10_EDGE)["artifacts"][68:]]


# Reads and the canonical hunks -----------------------------------------------------------------------------------------

SEMANTIC_FUNCTIONS = {"_era_bytes", "_verified", "_json", "_holds", "_bound", "_git_mode", "_texts", "_local_path",
                      "_era_import", "_era_model", "check_era_models", "era_models", "check_freeze", "check_new_files",
                      "check_contract_tree", "check_added_file", "validate_files", "check_status", "check_adoption",
                      "check_subject", "check_reviews", "_subject_named", "check_review", "check_redactions",
                      "check_carried", "check_slips", "validate_adoption", "check_edge_record", "check_new_row",
                      "check_registered_once", "validate_edge_record", "check_vector_replay", "check_definitions",
                      "validate_model", "validate_policy_observation_digests"}


def test_reviewed_bytes_is_the_only_semantic_read():
    tree = ast.parse(profile.regular_bytes(profile.VALIDATOR_PATH))
    seen = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in SEMANTIC_FUNCTIONS:
            seen.add(node.name)
            used = {name.id for name in ast.walk(node) if isinstance(name, ast.Name)}
            attributes = {attribute.attr for attribute in ast.walk(node) if isinstance(attribute, ast.Attribute)}
            assert not used & {"regular_bytes", "open"}, node.name
            assert not attributes & {"read_bytes", "read_text", "open", "lstat", "stat", "iterdir", "glob", "rglob"}, node.name
    assert seen == SEMANTIC_FUNCTIONS


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


# Every check can fail (252's packet review lesson P1-1: no check without a failing test) ------------------------------

CHECK_TESTS = {
    "MET-ENFORCE-041 reviewed bytes are bound: ": "test_a_path_outside_the_era_is_refused_before_it_is_read",
    "unreviewed DIGEST-CONTRACT source: ": "test_every_era_file_is_bound_by_digest",
    "the model runs this era's frozen models: I06 v4 with I06 v1 and v3": "test_the_model_runs_this_eras_frozen_models",
    FREEZE: "test_no_earlier_contract_record_frozen_model_or_edge_record_changes",
    "the contract's files, records and briefs, the model and edge record v10 are new in this packet, each once":
        "test_the_contract_files_records_briefs_model_and_edge_record_are_new_each_once",
    "the contract directory is a directory, not a link":
        "test_the_contract_directory_is_closed_and_every_file_is_mode_100644",
    TREE_HOLDS: "test_the_contract_directory_is_closed_and_every_file_is_mode_100644",
    "a file this packet adds is a regular file of git mode 100644: ":
        "test_an_added_file_is_a_regular_file_of_mode_100644_without_a_local_path",
    "no absolute local path in a file this packet adds: ":
        "test_an_added_file_is_a_regular_file_of_mode_100644_without_a_local_path",
    "adopted DIGEST-CONTRACT status": "test_the_status_is_closed_and_records_the_adoption",
    "the adoption is the lane monitor's decision, verbatim": "test_the_adoption_is_the_monitors_decision_verbatim",
    "the contract files are the adopted candidate 4: ": "test_the_contract_files_are_the_adopted_bytes",
    "seven reviews in order; the last passed with NOTEs only on the adopted candidate 4":
        "test_seven_reviews_in_order_and_the_last_passed_with_notes_only",
    "review ": "test_each_review_is_bound_to_its_record_and_its_subject",
    "each published brief is the redacted copy its review names, by digest":
        "test_each_published_brief_is_the_redacted_copy_its_review_names",
    "the carried items are present, C1-1 first and carried to this packet's layer test":
        "test_the_carried_items_are_present_c1_1_first",
    "the slips are present, each with its ruling": "test_the_slips_are_present_each_with_its_ruling",
    EDGE_KEEPS: "test_edge_record_v10_supersedes_v9_and_carries_its_68_rows",
    EDGE_ROWS: "test_edge_record_v10_supersedes_v9_and_carries_its_68_rows",
    "edge record v10 row ": "test_each_new_row_registers_its_providers_exact_bytes_and_mode_before_use",
    "each provider path, and each new consumer path, is registered once":
        "test_each_provider_and_new_consumer_is_registered_once",
    "the model replays its vectors over this era's frozen files with no error":
        "test_a_changed_vector_or_frozen_file_fails_the_replay",
    "definitions.json is the model's definitions, by the vectors' canonical pin":
        "test_definitions_json_is_the_models_definitions_by_the_vectors_pin",
    "unreviewed current source: ": "test_the_canonical_check_reads_this_eras_bytes",
    "canonical byte-minimal inverse hunks: ": "test_whole_line_hunks_are_refused_where_canonical_ones_differ"}
NAMED_MESSAGES = {FREEZE: "FREEZE", TREE_HOLDS: "TREE_HOLDS", EDGE_KEEPS: "EDGE_KEEPS", EDGE_ROWS: "EDGE_ROWS"}


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


def _messages_of(name):
    """The expected messages a parametrized test lists in its parametrize marks."""
    rows = []
    for mark in getattr(globals()[name], "pytestmark", []):
        values = mark.args[1] if len(mark.args) > 1 else []
        for row in values:
            rows += [value for value in (row if isinstance(row, tuple) else (row,)) if isinstance(value, str)]
    return rows


# C1-1 (contract review round 1, ruled binding; the contract README section 10): the layer test runs VPO's
# validate_messages and VPC's validate_profile on the complete I01 positive, with no skip, expected-failure mark or import
# guard. `complete` is the complete I01 positive in the contract's vectors.json; CS is
# architecture/policy-observation-inputs/channel.schema.json and PPS architecture/proxy-contract-inputs/profile.schema.json.
# These assertions are the only executable check that the complete positive fits the I01 wire.

C1_VECTORS = profile.ROOT / "architecture/policy-observation-digests/vectors.json"
C1_CS = profile.ROOT / "architecture/policy-observation-inputs/channel.schema.json"
C1_PPS = profile.ROOT / "architecture/proxy-contract-inputs/profile.schema.json"


def _complete():
    return types.SimpleNamespace(**json.loads(C1_VECTORS.read_bytes())["complete"])


def test_c1_1_validate_messages_accepts_the_complete_positive():
    """(1) validate_messages(complete.binding, complete.request, complete.observation, complete.profile, CS,
    complete.now, complete.previous) == []"""
    complete, CS = _complete(), json.loads(C1_CS.read_bytes())
    assert validate_messages(complete.binding, complete.request, complete.observation, complete.profile, CS,
                             complete.now, complete.previous) == []


def test_c1_1_validate_profile_accepts_the_complete_positive():
    """(2) validate_profile(complete.profile, PPS) == []"""
    complete, PPS = _complete(), json.loads(C1_PPS.read_bytes())
    assert validate_profile(complete.profile, PPS) == []


@pytest.mark.parametrize("kind", ["ResourceQuota", "LimitRange", "ServiceAccount"])
def test_c1_1_each_refuses_when_one_preexisting_reference_changes(kind):
    """(3) each returns its refusal when one preexisting reference's observedDigest in complete.profile is changed."""
    complete, CS, PPS = _complete(), json.loads(C1_CS.read_bytes()), json.loads(C1_PPS.read_bytes())
    references = [ref for ref in complete.profile["capacityEntries"]["preexistingResourceRefs"] if ref["kind"] == kind]
    assert len(references) == 1
    changed = "sha256:" + ("1" * 64 if references[0]["observedDigest"] == "sha256:" + "0" * 64 else "0" * 64)
    assert changed != references[0]["observedDigest"]
    references[0]["observedDigest"] = changed
    assert validate_messages(complete.binding, complete.request, complete.observation, complete.profile, CS,
                             complete.now, complete.previous) == ["invalid protected observation data"]
    assert validate_profile(complete.profile, PPS) == ["invalid strict proxy profile data"]
