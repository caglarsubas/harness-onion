"""Exact source lineage for MET-GOV-001; the evolution surface record v1: the head keeps the full fan-in (8 own and 68 predecessor routes, every catalog walk and round trip, the full payload loop), and the semantic check (the freeze, the files added, the adoption with the owner's NOTE fold, the five review rounds, the contract's documents and the canonical hunks) has a failing case for every refusal, each on plain data. The candidate's own tests follow (the record, its schema and its reference model agree; every vector replays; the derived gate-material list; every file of this checkout in exactly one programme class)."""
import ast
import json
import copy
from copy import deepcopy
import os
import re
import stat
import types
from pathlib import Path
from types import MappingProxyType

import pytest

from scripts import validate_evolution_surface as profile
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


def packets():
    return {path.stem: safe_load(path.read_bytes())
            for path in (profile.ROOT / "task-packets").glob("*.yaml")}


def layer_packets():
    # The newer MET-ENFORCE-041 layer is projected away before this layer's payload checks.
    return profile.successor.historical_catalog(packets())


def changed_test():
    return next(path for path in profile._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert profile.validate() is None
    current = packets()
    accepted = profile.historical_catalog(current)
    assert len(current) == 268 and len(accepted) == 256
    assert set(accepted) == set(current) - {profile.NEW_PACKET, profile.successor.NEW_PACKET,
                                            profile.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET}
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


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "e9_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = profile.historical_bytes(path, raw) if route in ("current_test", "old_bytes") else None
    current_packets = packets() if route == "catalog" else None
    layer = layer_packets() if route == "payloads" else None
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
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
    with pytest.raises(ValueError, match="evolution surface history authority digest"):
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
    assert len(profile.historical_catalog(current)) == 256


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
    assert len(profile.historical_catalog(current)) == 256
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
    assert len(rules) == 257 and len(parsed) == 256
    assert profile._packet_rules() is rules and len(parsed) == 256
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
    with pytest.raises(ValueError, match="evolution surface history authority digest"):
        profile.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = layer_packets()
    profile.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "evolution-surface-authority.json").write_bytes(
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
    # The newer MET-ENFORCE-041 layer refuses a mutated validator before this layer.
    with pytest.raises(ValueError, match="unreviewed current source: scripts/validate_evolution_surface.py"):
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
            assert all("validate_" not in alias.name or alias.name == "validate_policy_observation_digests"
                       for alias in node.names)


def _count_authority_reads(monkeypatch):
    counts = {}
    for module in (profile.successor, profile, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner):
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
    expected = {module.__name__: 1 for module in (profile.successor, profile, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner)}
    if route == "current_test":
        # The forward route reads this layer's newest bytes and then projects them forward once more.
        assert all(counts[name] >= 1 for name in expected) and set(counts) == set(expected)
    else:
        assert counts == expected


# MET-GOV-001 (EVOLUTION-SURFACE-001): this era's check, and a failing case for every check. Every mutant below is
# applied to plain data handed to the layer's pure checks: nothing in the layer or the library is patched or swapped.

VALIDATE = profile.validate_evolution_surface
# Tamper values name packets, bases and files that already exist and that this record does not carry in the tampered
# place (edge record v8's packet, 253's merge, the I01 wire's validator), never a later packet id, so that no later
# packet's mechanics can turn a negative into a positive (the monitor's slot-253 catch).
OTHER_PACKET = "MET-ENFORCE-039"
OTHER_BASE = "585364b94e3e4a8bf1418ef750ce3d71cd38f95a"
OTHER_PATH = "scripts/validate_policy_observation.py"
ROUND5_README = profile.CONTRACT_DIR + "/round5/README.md"
ROUND5_MODEL = profile.CONTRACT_DIR + "/round5/scripts/evolution_surface.py"


def _load(path):
    return json.loads(profile.reviewed_bytes(path))


def _status():
    return _load(profile.STATUS_PATH)


def _records():
    return [_load(path) for path in profile.RECORDS]


def _reviewed():
    return {profile.README_PATH: profile._verified(ROUND5_README), profile.MODEL_PATH: profile._verified(ROUND5_MODEL)}


def test_the_contract_holds_for_this_era():
    assert VALIDATE() is None


def test_every_added_file_record_and_snapshot_is_pinned():
    pinned = set(profile.ERA_SHA256)
    assert len(profile.NEW_FILES) == 37 and len(set(profile.NEW_FILES)) == 37 and pinned == set(profile.NEW_FILES)
    assert len(profile.SNAPSHOTS) == 25 and len(profile.RECORDS) == 5 and len(profile.SNAPSHOT_DIRS) == 10
    assert len(profile.DIRECTORY_FILES) == 36 and profile.MODEL_PATH not in profile.DIRECTORY_FILES
    assert all(path.startswith(profile.CONTRACT_DIR + "/") for path in profile.DIRECTORY_FILES + profile.SNAPSHOT_DIRS)
    assert [row["record"] for row in _status()["rounds"]] == list(profile.RECORDS)
    for path, expected in profile.ERA_SHA256.items():
        assert profile.digest(profile.reviewed_bytes(path)) == expected


@pytest.mark.parametrize("path", sorted(profile.ERA_SHA256))
def test_every_era_file_is_bound_by_digest(path):
    raw = profile._verified(path)
    assert profile._era_bytes(path, raw) == raw
    for changed in (raw + b" ", bytearray(raw)):
        with pytest.raises(ValueError, match=re.escape("unreviewed EVOLUTION-SURFACE-001 source: " + path)):
            profile._era_bytes(path, changed)


def test_a_path_outside_the_era_is_refused_before_it_is_read():
    for path in (profile.CONTRACT_DIR + "/notes.md", profile.CONTRACT_DIR + "/round6/README.md", OTHER_PATH,
                 profile.VALIDATOR_PATH, "tests/test_evolution_surface.py", None):
        with pytest.raises(ValueError, match="MET-GOV-001 reviewed bytes are bound: "):
            profile._verified(path)
        with pytest.raises(ValueError, match="MET-GOV-001 reviewed bytes are bound: "):
            profile._era_bytes(path, b"")


# The freeze and the files this packet adds -----------------------------------------------------------------------------

FREEZE = ("no earlier contract, record or model changes, and under architecture/ only the contract's directory is "
          "added: ")


def _changed_and_added():
    return list(profile._PROJECTION_RULES), list(profile.authority()["newFiles"])


@pytest.mark.parametrize("path, where", [("architecture/edge-record-v9/status.json", "changed"),
                                         ("architecture/artifact-edges/README-v9.md", "changed"),
                                         (profile.MODEL_PATH, "changed"), (profile.README_PATH, "changed"),
                                         ("architecture/evolution-surface-v2/README.md", "added"),
                                         ("architecture/edge-record-v10/status.json", "added")])
def test_no_earlier_contract_record_or_model_changes(path, where):
    changed, added = _changed_and_added()
    profile.check_freeze(changed, added)
    assert not any(item.startswith("architecture/") for item in changed)
    if where == "added":
        added = added + [path]
    else:
        changed = changed + [path]
    with pytest.raises(ValueError, match=re.escape(FREEZE + path)):
        profile.check_freeze(changed, added)


@pytest.mark.parametrize("change", ["missing", "extra", "changed", "model_missing", "snapshot_missing"])
def test_the_contract_files_records_and_snapshots_are_new_each_once(change):
    changed, added = _changed_and_added()
    profile.check_new_files(added, changed)
    if change == "missing":
        added.remove(profile.STATUS_PATH)
    elif change == "extra":
        added.append(profile.CONTRACT_DIR + "/review-round6.json")
    elif change == "changed":
        changed.append(profile.RECORDS[0])
    elif change == "model_missing":
        added.remove(profile.MODEL_PATH)
    else:
        added = [path for path in added if path != profile.SNAPSHOTS[0]]
    with pytest.raises(ValueError, match="the contract's files, records and round snapshots are new in this packet, "
                                         "each once"):
        profile.check_new_files(added, changed)


@pytest.mark.parametrize("change, message", [
    ("extra", "the contract directory holds exactly its files and five round snapshots, each file of mode 100644"),
    ("missing", "the contract directory holds exactly its files and five round snapshots, each file of mode 100644"),
    ("executable", "the contract directory holds exactly its files and five round snapshots, each file of mode 100644"),
    ("link", "the contract directory holds exactly its files and five round snapshots, each file of mode 100644"),
    ("snapshot_link", "the contract directory holds exactly its files and five round snapshots, each file of mode 100644"),
    ("directory_link", "the contract directory is a directory, not a link")])
def test_the_contract_directory_is_closed_and_every_file_is_mode_100644(change, message):
    mode, tree = profile.reviewed_mode(profile.CONTRACT_DIR), profile.reviewed_tree(profile.CONTRACT_DIR)
    assert sorted(tree) == sorted(profile.DIRECTORY_FILES + profile.SNAPSHOT_DIRS) and stat.S_ISDIR(mode)
    profile.check_contract_tree(mode, tree)
    tree = dict(tree)
    if change == "extra":
        tree[profile.CONTRACT_DIR + "/round6"] = stat.S_IFDIR | 0o755
    elif change == "missing":
        del tree[profile.RECORDS[4]]
    elif change == "executable":
        tree[profile.STATUS_PATH] = stat.S_IFREG | 0o755
    elif change == "link":
        tree[profile.SNAPSHOTS[0]] = stat.S_IFLNK | 0o777
    elif change == "snapshot_link":
        tree[profile.SNAPSHOT_DIRS[0]] = stat.S_IFLNK | 0o777
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
    # A list of the scanned-for patterns names no path.
    profile.check_added_file(path, mode, raw + b" /" + b"users/, /" + b"private/, .local" + b"/state, email pattern")


# The adoption -------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("change", ["schema", "work_item", "packet", "state", "contract_value", "contract_order",
                                    "reviewed_commit", "reviewed_order", "owner_decision", "owner_order", "non_claim",
                                    "extra_key", "missing_key", "key_order"])
def test_the_status_is_closed_and_records_the_adoption(change):
    status = _status()
    profile.check_status(status)
    if change == "schema":
        status["schemaVersion"] = "planeon.internal.edge-record-v9-status/v1"
    elif change == "work_item":
        status["workItem"] = "EDGE-V9"
    elif change == "packet":
        status["packet"] = OTHER_PACKET
    elif change == "state":
        status["status"] = "CONTRACT_CANDIDATE"
    elif change == "contract_value":
        status["contract"]["model"] = OTHER_PATH
    elif change == "contract_order":
        status["contract"] = dict(reversed(list(status["contract"].items())))
    elif change == "reviewed_commit":
        status["reviewedSubject"]["commit"] = OTHER_BASE
    elif change == "reviewed_order":
        status["reviewedSubject"] = dict(reversed(list(status["reviewedSubject"].items())))
    elif change == "owner_decision":
        status["ownerDecisions"][0] = status["ownerDecisions"][0].replace("(Recommended)", "")
    elif change == "owner_order":
        status["ownerDecisions"].reverse()
    elif change == "non_claim":
        status["nonClaims"].pop()
    elif change == "extra_key":
        status["baseMain"] = OTHER_BASE
    elif change == "missing_key":
        del status["nonClaims"]
    else:
        status["workItem"] = status.pop("workItem")
    with pytest.raises(ValueError, match="adopted evolution surface status"):
        profile.check_status(status)


@pytest.mark.parametrize("path", profile.SUBJECT)
def test_the_contract_files_are_the_adopted_bytes(path):
    raw = profile._verified(path)
    profile.check_subject(path, raw)
    for changed in (raw + b"\n", raw.replace(b"\n", b"\r\n", 1), None):
        with pytest.raises(ValueError, match=re.escape("the contract files are the adopted bytes: " + path)):
            profile.check_subject(path, changed)


FOLD_CHANGES = ["commit", "tree", "decision", "ruling", "item", "check", "reviewed_digest", "fold_digest", "files_order",
                "file_key", "file_dropped", "extra_key", "key_order", "snapshot_readme", "snapshot_model",
                "reviewed_missing"]


@pytest.mark.parametrize("change", FOLD_CHANGES)
def test_the_owners_note_fold_is_bound_by_digest(change):
    status, readme, reviewed = _status(), profile._verified(profile.README_PATH), _reviewed()
    profile.check_fold(status, readme, reviewed)
    fold = status["noteFold"]
    assert fold["items"] == ["G1R5-1", "G1R5-2", "G1R5-3", "G1R5-4"] and fold["commit"].startswith("82186be4")
    if change == "commit":
        fold["commit"] = status["reviewedSubject"]["commit"]
    elif change == "tree":
        fold["tree"] = status["reviewedSubject"]["tree"]
    elif change == "decision":
        fold["decision"] = "Run a round 6"
    elif change == "ruling":
        fold["ruling"] = "MON-GOV-R4-KEEP"
    elif change == "item":
        fold["items"].pop()
    elif change == "check":
        fold["check"] = ""
    elif change == "reviewed_digest":
        fold["files"][profile.MODEL_PATH]["reviewedSha256"] = fold["files"][profile.MODEL_PATH]["foldSha256"]
    elif change == "fold_digest":
        fold["files"][profile.VECTORS_PATH]["foldSha256"] = "0" * 64
    elif change == "files_order":
        fold["files"] = dict(reversed(list(fold["files"].items())))
    elif change == "file_key":
        fold["files"][profile.README_PATH]["note"] = "x"
    elif change == "file_dropped":
        del fold["files"]["tests/test_evolution_surface.py"]
    elif change == "extra_key":
        fold["base"] = OTHER_BASE
    elif change == "key_order":
        fold["commit"] = fold.pop("commit")
    elif change == "snapshot_readme":
        reviewed[profile.README_PATH] = readme
    elif change == "snapshot_model":
        reviewed[profile.MODEL_PATH] = reviewed[profile.MODEL_PATH] + b"\n"
    else:
        del reviewed[profile.MODEL_PATH]
    with pytest.raises(ValueError, match="the owner's NOTE fold is bound by digest: G1R5-1 to G1R5-4 on round 5's "
                                         "subject"):
        profile.check_fold(status, readme, reviewed)


@pytest.mark.parametrize("change", ["path", "replaced", "with", "fold_digest", "adopted_digest", "readme_bytes",
                                    "old_line_back", "edited_elsewhere", "extra_key", "key_order"])
def test_the_readme_status_line_is_the_one_adoption_edit(change):
    status, readme, reviewed = _status(), profile._verified(profile.README_PATH), _reviewed()
    profile.check_fold(status, readme, reviewed)
    edit = status["adoptionEdit"]
    assert edit["replaced"] == profile.STATUS_BEFORE and edit["with"] == profile.STATUS_AFTER
    if change == "path":
        edit["path"] = profile.BRIEF_PATH
    elif change == "replaced":
        edit["replaced"] = edit["replaced"].replace("pending", "round 4")
    elif change == "with":
        edit["with"] = edit["with"].replace("ADOPTED_", "")
    elif change == "fold_digest":
        edit["foldSha256"] = edit["adoptedSha256"]
    elif change == "adopted_digest":
        edit["adoptedSha256"] = edit["foldSha256"]
    elif change == "readme_bytes":
        readme = readme + b"\n"
    elif change == "old_line_back":
        readme = readme + profile.STATUS_BEFORE.encode("utf-8")
    elif change == "edited_elsewhere":
        # Packet review r1 P1-1: a README changed outside the status line, with its digest updated, is not the fold's.
        assert readme.count(b"## What this contract is\n") == 1
        readme = readme.replace(b"## What this contract is\n", b"## What this contract says\n")
        edit["adoptedSha256"] = profile.digest(readme)
    elif change == "extra_key":
        edit["note"] = "x"
    else:
        edit["path"] = edit.pop("path")
    with pytest.raises(ValueError, match="the README's status line is the one adoption edit"):
        profile.check_fold(status, readme, reviewed)


@pytest.mark.parametrize("change", ["reordered", "one_round", "first_verdict", "last_verdict", "last_subject",
                                    "last_minor"])
def test_five_rounds_in_order_and_the_fifth_passed_with_notes_only(change):
    rounds = _status()["rounds"]
    profile.check_rounds(rounds)
    if change == "reordered":
        rounds.reverse()
    elif change == "one_round":
        rounds.pop(0)
    elif change == "first_verdict":
        rounds[0]["verdict"] = "PASS_FOR_ADOPTION"
    elif change == "last_verdict":
        rounds[-1]["verdict"] = "CHANGES_REQUIRED"
    elif change == "last_subject":
        rounds[-1]["subject"] = rounds[3]["subject"]
    else:
        rounds[-1]["severities"] = ["MINOR", "NOTE"]
    with pytest.raises(ValueError, match="five review rounds in order; the fifth passed with NOTEs only on round 5's "
                                         "subject"):
        profile.check_rounds(rounds)


ROUND_CHANGES = ["record_bytes", "record_digest", "record_path", "row_round", "row_subject", "row_tree", "row_verdict",
                 "row_snapshot", "row_vectors", "row_severities", "row_key", "record_schema", "record_round",
                 "record_commit", "record_tree", "record_verdict", "finding_dropped", "finding_renamed", "record_key"]


@pytest.mark.parametrize("number", [1, 2, 3, 4, 5])
@pytest.mark.parametrize("change", ROUND_CHANGES)
def test_each_round_is_bound_to_its_record_and_its_subject(number, change):
    row = _status()["rounds"][number - 1]
    raw = profile._verified(profile.RECORDS[number - 1])
    record = json.loads(raw)
    profile.check_round(number, row, record, raw)
    other = 1 if number != 1 else 2
    if change == "record_bytes":
        raw = raw + b"\n"
    elif change == "record_digest":
        row["recordSha256"] = "0" * 64
    elif change == "record_path":
        row["record"] = profile.RECORDS[other - 1]
    elif change == "row_round":
        row["round"] = other
    elif change == "row_subject":
        row["subject"] = OTHER_BASE
    elif change == "row_tree":
        row["subjectTree"] = "0" * 40
    elif change == "row_verdict":
        row["verdict"] = "PASS" if number < 5 else "CHANGES_REQUIRED"
    elif change == "row_snapshot":
        row["snapshot"] = profile.CONTRACT_DIR + "/round%d/" % other
    elif change == "row_vectors":
        row["digestOnly"][profile.VECTORS_PATH] = "0" * 64
    elif change == "row_severities":
        row["severities"] = ["MAJOR"] + row["severities"]
    elif change == "row_key":
        row["absent"] = []
    elif change == "record_schema":
        record["schemaVersion"] = "harness.planeon.ai/mas-contract-review/v1"
    elif change == "record_round":
        record["round"] = other
    elif change == "record_commit":
        record["subjectCommit"] = OTHER_BASE
    elif change == "record_tree":
        record["subjectTree"] = "0" * 40
    elif change == "record_verdict":
        record["verdict"] = "PASS_FOR_ADOPTION" if number < 5 else "CHANGES_REQUIRED"
    elif change == "finding_dropped":
        record["findings"].pop()
    elif change == "finding_renamed":
        record["findings"][0]["id"] = "G1R9-1"
    else:
        record["notes"] = []
    with pytest.raises(ValueError, match=re.escape("review round %d is bound to its record and its subject" % number)):
        profile.check_round(number, row, record, raw)


@pytest.mark.parametrize("change", ["item", "severity", "to", "action", "dropped", "extra", "key_order"])
def test_round_5s_notes_are_carried_to_the_fold(change):
    status, records = _status(), _records()
    profile.check_carried(status, records[-1])
    carried = status["carried"]
    assert [row["item"] for row in carried] == ["G1R5-1", "G1R5-2", "G1R5-3", "G1R5-4"]
    if change == "item":
        carried[0]["item"] = "G1R5-9"
    elif change == "severity":
        carried[1]["severity"] = "MINOR"
    elif change == "to":
        carried[2]["to"] = "the packet review"
    elif change == "action":
        carried[3]["action"] = ""
    elif change == "dropped":
        carried.pop()
    elif change == "extra":
        carried.append(dict(carried[0]))
    else:
        carried[0]["item"] = carried[0].pop("item")
    with pytest.raises(ValueError, match="round 5's four NOTEs are carried to the owner's fold, each with its action"):
        profile.check_carried(status, records[-1])


@pytest.mark.parametrize("change", ["record", "schema", "vectors", "record_type"])
def test_the_record_its_schema_and_its_vectors_name_the_same_contract(change):
    record, schema, vectors = (_load(profile.RECORD_PATH), _load(profile.SCHEMA_PATH), _load(profile.VECTORS_PATH))
    profile.check_documents(record, schema, vectors)
    if change == "record":
        record["schemaVersion"] = "planeon.internal.evolution-surface/v2"
    elif change == "schema":
        schema["$id"] = "planeon.internal.evolution-surface/v0"
    elif change == "vectors":
        vectors["schemaVersion"] = "planeon.internal.topology-coordination-vectors/v1"
    else:
        record = [record]
    with pytest.raises(ValueError, match="the record, its schema and its vectors name the same contract"):
        profile.check_documents(record, schema, vectors)


def test_the_restated_values():
    status = _status()
    assert profile.REVIEWED_SUBJECT == status["reviewedSubject"] and profile.REVIEWED_SUBJECT["commit"].startswith("72901245")
    assert profile.FOLD["commit"].startswith("82186be4") and profile.FOLD["tree"].startswith("6cc2acd5")
    assert [row[0] for row in profile.ROUNDS] == [1, 2, 3, 4, 5]
    assert [row[3] for row in profile.ROUNDS] == ["CHANGES_REQUIRED"] * 4 + ["PASS_FOR_ADOPTION"]
    assert [len(row[5]) for row in profile.ROUNDS] == [10, 4, 3, 2, 4]
    assert profile.CARRIED_TO == "the owner's NOTE fold (82186be4)"
    assert len(profile.OWNER_DECISIONS) == 8 and len(profile.NON_CLAIMS) == 3
    assert profile.ADOPTED_SHA256[profile.MODEL_PATH] == profile.FOLD_FILES[profile.MODEL_PATH][1]
    assert profile.ADOPTED_SHA256[profile.VECTORS_PATH] == profile.FOLD_FILES[profile.VECTORS_PATH][1]
    assert profile.PREVIOUS_PACKET == "MET-ENFORCE-040" and profile.NEW_PACKET == "MET-GOV-001"


# Reads and the canonical hunks -----------------------------------------------------------------------------------------

SEMANTIC_FUNCTIONS = {"_era_bytes", "_verified", "_json", "_holds", "_bound", "_git_mode", "_local_path",
                      "check_freeze", "check_new_files", "check_contract_tree", "check_added_file", "validate_files",
                      "check_status", "check_subject", "check_fold", "check_rounds", "check_round", "check_carried",
                      "validate_adoption", "check_documents", "validate_contract", "validate_evolution_surface"}


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
    "MET-GOV-001 reviewed bytes are bound: ": "test_a_path_outside_the_era_is_refused_before_it_is_read",
    "unreviewed EVOLUTION-SURFACE-001 source: ": "test_every_era_file_is_bound_by_digest",
    FREEZE: "test_no_earlier_contract_record_or_model_changes",
    "the contract's files, records and round snapshots are new in this packet, each once":
        "test_the_contract_files_records_and_snapshots_are_new_each_once",
    "the contract directory is a directory, not a link":
        "test_the_contract_directory_is_closed_and_every_file_is_mode_100644",
    "the contract directory holds exactly its files and five round snapshots, each file of mode 100644":
        "test_the_contract_directory_is_closed_and_every_file_is_mode_100644",
    "a file this packet adds is a regular file of git mode 100644: ":
        "test_an_added_file_is_a_regular_file_of_mode_100644_without_a_local_path",
    "no absolute local path in a file this packet adds: ":
        "test_an_added_file_is_a_regular_file_of_mode_100644_without_a_local_path",
    "adopted evolution surface status": "test_the_status_is_closed_and_records_the_adoption",
    "the contract files are the adopted bytes: ": "test_the_contract_files_are_the_adopted_bytes",
    "the owner's NOTE fold is bound by digest: G1R5-1 to G1R5-4 on round 5's subject":
        "test_the_owners_note_fold_is_bound_by_digest",
    "the README's status line is the one adoption edit": "test_the_readme_status_line_is_the_one_adoption_edit",
    "five review rounds in order; the fifth passed with NOTEs only on round 5's subject":
        "test_five_rounds_in_order_and_the_fifth_passed_with_notes_only",
    "review round ": "test_each_round_is_bound_to_its_record_and_its_subject",
    "round 5's four NOTEs are carried to the owner's fold, each with its action":
        "test_round_5s_notes_are_carried_to_the_fold",
    "the record, its schema and its vectors name the same contract":
        "test_the_record_its_schema_and_its_vectors_name_the_same_contract",
    "unreviewed current source: ": "test_the_canonical_check_reads_this_eras_bytes",
    "canonical byte-minimal inverse hunks: ": "test_whole_line_hunks_are_refused_where_canonical_ones_differ"}


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
    """Every refusal of the semantic check is mapped to a test, and that test names the refusal (in its body or its
    parametrized expected messages)."""
    import inspect
    assert _refusal_messages() == set(CHECK_TESTS)
    for message, name in CHECK_TESTS.items():
        test = globals()[name]
        assert callable(test) and name.startswith("test_")
        source = inspect.getsource(test)
        assert (message[:40] in source or any(message.startswith(text) for text in _messages_of(name))
                or (message == FREEZE and "FREEZE" in source)), message


def _messages_of(name):
    """The expected messages a parametrized test lists in its parametrize marks."""
    rows = []
    for mark in getattr(globals()[name], "pytestmark", []):
        values = mark.args[1] if len(mark.args) > 1 else []
        for row in values:
            rows += [value for value in (row if isinstance(row, tuple) else (row,)) if isinstance(value, str)]
    return rows


# The candidate's own tests (MET-GOV-001 contract candidate, as the owner's NOTE fold left them) ---------------------------
import ast
import copy
import json
import os
from pathlib import Path

import jsonschema
import pytest

from scripts import evolution_surface as es

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "architecture/evolution-surface"
RECORD = es.load((HERE / "evolution-surface.json").read_bytes())
VECTORS = json.loads((HERE / "vectors.json").read_bytes())
SCHEMA = json.loads((HERE / "evolution-surface.schema.json").read_bytes())
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)


def code_of(doc):
    try:
        es.check(doc)
        return None
    except es.Refused as refusal:
        return refusal.code


def test_the_schema_is_a_valid_draft_2020_12_schema():
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    assert SCHEMA["$id"] == es.SCHEMA == RECORD["schemaVersion"]


def test_the_record_is_valid_and_pinned_by_the_vectors():
    facts = es.check(RECORD)
    assert facts["digest"] == VECTORS["recordDigest"]
    assert VALIDATOR.is_valid(RECORD)


def test_every_vector_replays():
    counts = es.replay(RECORD, VECTORS)
    assert counts["decisions"] == 44 and counts["invariants"] == 31 and counts["requests"] == 10
    assert counts["paths"] == 23 and counts["prs"] == 9
    assert counts["derived"] == 31 and counts["consumerCases"] == 12


def test_a_changed_vector_is_a_mismatch_even_without_asserts():
    # replay raises es.Mismatch explicitly, so `python -O` cannot strip the check (G1R1-10)
    changed = json.loads(json.dumps(VECTORS))
    changed["decisions"][0]["expect"] = {"decision": "ALLOWED", "reasons": []}
    with pytest.raises(es.Mismatch):
        es.replay(RECORD, changed)


def test_every_invariant_code_has_a_refusing_vector():
    expected = {row["expect"] for row in VECTORS["invariants"]}
    assert expected == set(es.CODES) - {"COVERAGE"}


def _shape_probes():
    """Records that differ from the valid record by one shape fault each, plus every invariant vector's record."""
    probes = [("record", RECORD)]
    probes += [(row["id"], es.mutate(RECORD, row["mutation"])) for row in VECTORS["invariants"]]
    probes += [(row["id"], row["record"]) for row in VECTORS["paths"] if "record" in row]
    faults = (("delete", None), ("null", None), ("int", 7), ("text", "x"), ("list", []), ("object", {}),
              ("bool", True), ("newline", "\n"))
    targets = [["schemaVersion"], ["surfaceId"], ["version"], ["operations"], ["levels"], ["levels", "product"],
               ["levels", "programme", "coverageSkip"], ["levels", "programme", "coverageSkip", "rootNames"],
               ["levels", "programme", "coverageSkip", "anyDepthFilePatterns", 0]]
    for level in ("product", "programme"):
        targets += [["levels", level, "roles"], ["levels", level, "roles", 0], ["levels", level, "roles", 0, "id"],
                    ["levels", level, "roles", 0, "kind"], ["levels", level, "roles", 0, "description"],
                    ["levels", level, "classes"]]
        for key in ("id", "description", "neverAutonomous", "appendOnly", "twoPerson", "approvalBinding", "governs",
                    "independentOf", "operations", "grounds"):
            targets.append(["levels", level, "classes", 0, key])
        targets += [["levels", level, "classes", 0, "operations", "approve"],
                    ["levels", level, "classes", 0, "operations", "approve", 0],
                    ["levels", level, "classes", 0, "grounds", 0]]
    targets += [["levels", "product", "roles", 0, "plane"], ["levels", "programme", "classes", 0, "paths"],
                ["levels", "programme", "classes", 0, "paths", 0], ["levels", "programme", "classes", 0, "paths", 0,
                                                                    "prefix"],
                ["levels", "programme", "classes", "#ORACLE_TESTS", "paths", 0, "name"],
                ["levels", "programme", "classes", "#ORACLE_TESTS", "paths", 0, "under"]]
    for target in targets:
        for name, value in faults:
            step = {"path": target, "delete": True} if name == "delete" else {"path": target, "value": value}
            probes.append(("%s:%s" % ("/".join(map(str, target)), name), es.mutate(RECORD, [step])))
    # a valid value with a final newline, for every patterned field (the patterns end with (?![\s\S]), not $)
    patterned = [["surfaceId"], ["levels", "product", "roles", 0, "id"], ["levels", "programme", "classes", 0, "id"],
                 ["levels", "product", "classes", 0, "operations", "approve", 0],
                 ["levels", "programme", "classes", "#ORACLE_TESTS", "independentOf", 0],
                 ["levels", "programme", "classes", 0, "paths", 0, "prefix"],
                 ["levels", "programme", "classes", "#GATE_CI", "paths", 2, "exact"],
                 ["levels", "programme", "classes", "#ORACLE_TESTS", "paths", 0, "under"],
                 ["levels", "programme", "classes", "#ORACLE_TESTS", "paths", 0, "name"],
                 ["levels", "programme", "coverageSkip", "rootNames", 0],
                 ["levels", "programme", "coverageSkip", "anyDepthFilePatterns", 0]]
    for target in patterned:
        node = RECORD
        for key in target:
            node = es._step(node, key) if type(key) is str and key.startswith("#") else node[key]
        probes.append(("%s:newline" % "/".join(map(str, target)), es.mutate(RECORD, [{"path": target,
                                                                                      "value": node + "\n"}])))
    return probes


def test_the_model_refuses_as_shape_exactly_when_the_schema_rejects():
    disagreements = []
    probes = _shape_probes()
    for name, doc in probes:
        schema_rejects = not VALIDATOR.is_valid(doc)
        model_shape = code_of(doc) == "SHAPE"
        if schema_rejects != model_shape:
            disagreements.append(name)
    assert disagreements == [] and len(probes) > 400


def test_beyond_the_schema_only_i_json_faults_are_shape():
    # The schema judges I-JSON values; a value that is not I-JSON (here a lone surrogate built in memory, which load()
    # refuses in text form) passes the schema but the model refuses it as SHAPE: the model is only stricter (G1R1-2).
    lone = es.mutate(RECORD, [{"path": ["levels", "product", "roles", 0, "description"], "value": "x\ud800"}])
    assert VALIDATOR.is_valid(lone) and code_of(lone) == "SHAPE"
    with pytest.raises(es.Refused):
        es.load(json.dumps(lone))


def test_allowed_carries_no_reasons_and_every_denial_starts_with_not_listed():
    for level in es.LEVELS:
        roles = [r["id"] for r in RECORD["levels"][level]["roles"]]
        for c in RECORD["levels"][level]["classes"]:
            for op in es.OPS:
                for role in roles:
                    got = es.decide(RECORD, level, role, c["id"], op)
                    if role in c["operations"][op]:
                        assert got == {"decision": "ALLOWED", "reasons": []}
                        # computed, not assumed: a listed request meets none of the five other reasons (G1R1-7)
                        assert not _reasons_beyond_listing(level, role, c, op)
                    else:
                        assert got["decision"] == "DENIED" and got["reasons"][0] == "NOT_LISTED"
                        assert got["reasons"] == [r for r in es.REASONS if r in got["reasons"]]


def _reasons_beyond_listing(level, role, c, op):
    kinds = {r["id"]: r["kind"] for r in RECORD["levels"][level]["roles"]}
    classes = {k["id"]: k for k in RECORD["levels"][level]["classes"]}
    ops = c["operations"]
    found = []
    if c["neverAutonomous"] and kinds[role] == "AGENT" and op in ("approve", "activate"):
        found.append("NEVER_AUTONOMOUS")
    if op == "approve" and role in c["governs"]:
        found.append("SELF_GOVERNANCE")
    if op == "approve" and kinds[role] != "HUMAN" and role in ops["generate"] + ops["test"]:
        found.append("SEPARATION_OF_DUTIES")
    if c["appendOnly"] and op in ("approve", "activate"):
        found.append("APPEND_ONLY")
    if op == "generate" and any(role in classes[k]["operations"]["generate"] for k in classes
                                if k != c["id"] and (k in c["independentOf"] or c["id"] in classes[k]["independentOf"])):
        found.append("INDEPENDENCE")
    return found


def test_unknown_names_in_a_request_are_refused():
    for args in (("planet", "OWNER", "GATE_CI", "approve"), ("programme", "NOBODY", "GATE_CI", "approve"),
                 ("programme", "OWNER", "NO_CLASS", "approve"), ("programme", "OWNER", "GATE_CI", "merge"),
                 ("product", "OWNER", "GATE_CI", "approve"), ("programme", ["OWNER"], "GATE_CI", "approve"),
                 ("programme", "OWNER", {"c": 1}, "approve"), (None, "OWNER", "GATE_CI", "approve")):
        with pytest.raises(es.Refused) as refusal:
            es.decide(RECORD, *args)
        assert refusal.value.code == "UNKNOWN_REFERENCE"


@pytest.mark.parametrize("path", ["", "/abs", "a//b", "./a", "a/../b", "a/", "a\x00b", None, 3])
def test_a_malformed_path_is_refused(path):
    with pytest.raises(es.Refused) as refusal:
        es.resolve(RECORD, path)
    assert refusal.value.code == "SHAPE"


def test_the_derivation_is_pa_d5_plus_exactly_the_owner_accepted_extensions():
    derivation = VECTORS["derivation"]
    accepted = [e for group in derivation["acceptedExtensions"] for e in group["entries"]]
    assert es.derive_gate_material(RECORD) == sorted(derivation["paD5"] + accepted, key=es.canonical)
    assert len(derivation["paD5"]) == 6 and len(accepted) == 25
    assert [group["id"] for group in derivation["acceptedExtensions"]] == (
        ["D1-i"] + ["C%d" % n for n in range(1, 14)] + ["RR2"])


def test_every_file_of_this_checkout_falls_in_exactly_one_class():
    report = es.check_coverage(RECORD, ROOT)
    assert report["unclassified"] == [] and report["ambiguous"] == []
    assert report["files"] > 2000 and sum(report["perClass"].values()) == report["files"]


def test_the_tree_listing_skips_by_components_and_never_follows_links(tmp_path):
    for rel in (".git", ".github/workflows/verify.yml", ".venv/lib/x.py", "docs/.venv/y.md", "a/__pycache__/m.pyc",
                "a/m.pyc", "a/.DS_Store", "a/b.py", "dist/z.txt"):
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x")
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "hidden.txt").write_text("x")
    os.symlink(tmp_path / "outside", tmp_path / "linked")
    listed = es.tree_paths(RECORD, tmp_path)
    assert listed == sorted([".github/workflows/verify.yml", "docs/.venv/y.md", "a/b.py", "dist/z.txt",
                             "outside/hidden.txt", "linked"])


def test_an_unclassified_file_fails_the_coverage_check(tmp_path):
    for rel in ("README.md", "ci/x.py", "NEWFILE.md"):
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x")
    with pytest.raises(es.Refused) as refusal:
        es.check_coverage(RECORD, tmp_path)
    assert refusal.value.code == "COVERAGE"


@pytest.mark.parametrize("make", ["missing", "file", "link"])
def test_the_tree_walk_fails_closed_on_a_bad_root(tmp_path, make):
    root = tmp_path / "root"
    if make == "file":
        root.write_text("x")
    elif make == "link":
        (tmp_path / "real").mkdir()
        os.symlink(tmp_path / "real", root)
    with pytest.raises(es.Refused) as refusal:
        es.check_coverage(RECORD, root)
    assert refusal.value.code == "COVERAGE"


def test_an_unreadable_directory_fails_the_walk(tmp_path):
    (tmp_path / "docs" / "locked").mkdir(parents=True)
    (tmp_path / "docs" / "locked" / "NEW.md").write_text("x")
    (tmp_path / "README.md").write_text("x")
    os.chmod(tmp_path / "docs" / "locked", 0)
    try:
        if os.access(tmp_path / "docs" / "locked", os.R_OK):
            pytest.skip("running with privileges that read any directory")
        with pytest.raises(es.Refused) as refusal:
            es.tree_paths(RECORD, tmp_path)
        assert refusal.value.code == "COVERAGE"
    finally:
        os.chmod(tmp_path / "docs" / "locked", 0o755)


@pytest.mark.parametrize("link,target,refused", [
    ("ci/served.py", "../docs/data.md", True),       # a link at a gate path serving data
    ("docs/view.py", "../ci/real.py", True),          # a data link reaching a gate file
    ("docs/tree", "../ci", True),                     # a data link reaching a gate directory
    ("docs/all", "..", True),                         # a data link reaching the whole tree
    ("docs/other.md", "data.md", False),              # a data link to data
])
def test_a_symbolic_link_may_not_be_or_reach_gate_material(tmp_path, link, target, refused):
    for rel in ("README.md", "docs/data.md", "ci/real.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    os.symlink(target, tmp_path / link)
    if refused:
        with pytest.raises(es.Refused) as refusal:
            es.check_coverage(RECORD, tmp_path)
        assert refusal.value.code == "COVERAGE"
    else:
        assert es.check_coverage(RECORD, tmp_path)["unclassified"] == []


@pytest.mark.parametrize("link,target", [
    ("ci/__pycache__", "../docs/cache"),               # a gate-path link named like a cache directory (G1R2-1)
    ("ci/real.cpython-312.pyc", "../docs/data.pyc"),    # a gate-path link named like bytecode
    ("ci/.DS_Store", "../docs/data.md"),                # a gate-path link named like a skipped file
    ("docs/__pycache__", "../ci"),                      # a data link named like a cache directory reaching a gate dir
    (".venv", "ci"),                                    # a root skip-name link reaching a gate dir
    ("docs/up", "../.."),                               # a data link to an ancestor of the tree (G1R2-2)
    ("docs/gone", "../nowhere"),                        # a dangling link
])
def test_every_link_is_judged_whatever_its_name_and_target(tmp_path, link, target):
    for rel in ("README.md", "docs/data.md", "docs/data.pyc", "docs/cache/x.md", "ci/real.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    os.symlink(target, tmp_path / link)
    with pytest.raises(es.Refused) as refusal:
        es.check_coverage(RECORD, tmp_path)
    assert refusal.value.code == "COVERAGE"


def test_a_link_target_is_judged_by_identity_not_spelling(tmp_path):
    # On a case-insensitive file system ../CI reaches ci/; on a case-sensitive one it dangles. Both are refused (G1R2-2).
    for rel in ("README.md", "docs/data.md", "ci/real.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    os.symlink("../CI", tmp_path / "docs" / "caps")
    with pytest.raises(es.Refused) as refusal:
        es.check_coverage(RECORD, tmp_path)
    assert refusal.value.code == "COVERAGE"


def test_an_entry_that_cannot_be_examined_fails_closed(tmp_path):
    (tmp_path / "docs" / "listed").mkdir(parents=True)
    (tmp_path / "docs" / "listed" / "x.md").write_text("x")
    (tmp_path / "README.md").write_text("x")
    os.chmod(tmp_path / "docs" / "listed", 0o444)  # listable, not searchable (G1R2-4)
    try:
        if os.access(tmp_path / "docs" / "listed" / "x.md", os.F_OK):
            pytest.skip("running with privileges that search any directory")
        with pytest.raises(es.Refused) as refusal:
            es.check_coverage(RECORD, tmp_path)
        assert refusal.value.code == "COVERAGE"
    finally:
        os.chmod(tmp_path / "docs" / "listed", 0o755)


def test_skip_named_links_are_judged_but_not_classified(tmp_path):
    root, outside = tmp_path / "root", tmp_path / "venv"
    outside.mkdir()
    for rel in ("README.md", "docs/data.md"):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text("x")
    os.symlink(outside, root / ".venv")   # a sibling outside the tree: allowed, and not classified
    report = es.check_coverage(RECORD, root)
    assert report["files"] == 2 and ".venv" not in es.tree_paths(RECORD, root)
    os.symlink(tmp_path, root / "docs" / "up")   # the tree's parent reaches the whole tree: refused
    with pytest.raises(es.Refused) as refusal:
        es.check_coverage(RECORD, root)
    assert refusal.value.code == "COVERAGE"


@pytest.mark.parametrize("link,target", [
    ("ci/__pycache__/real.cpython-312.pyc", "../../docs/data.pyc"),  # a link inside a skip directory (G1R3-1)
    ("docs/__pycache__/l", "../../ci"),                             # a data link inside a skip directory
    ("docs/.pytest_cache/l", "../../ci"),
    ("docs/harnesses", "../task-packets/p"),                        # a link in place of a gate directory (G1R3-2)
    ("tests/fixtures/zero-bill", "../../docs/cache"),
    ("docs/alpha-2", "../task-packets/p"),                          # holds gate docs (C5, C13 and the verifier doc)
    ("architecture/evolution-surface", "../docs/cache"),
])
def test_links_inside_skip_directories_and_in_place_of_gate_directories_are_refused(tmp_path, link, target):
    for rel in ("README.md", "docs/data.md", "docs/data.pyc", "docs/cache/x.md", "ci/real.py", "task-packets/p/x.yaml",
                "ci/__pycache__/keep.txt", "docs/__pycache__/keep.txt", "docs/.pytest_cache/keep.txt"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    (tmp_path / link).parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target, tmp_path / link)
    with pytest.raises(es.Refused) as refusal:
        es.check_coverage(RECORD, tmp_path)
    assert refusal.value.code == "COVERAGE"
    assert es._gate_link(RECORD, str(tmp_path), link)


def test_a_root_link_in_place_of_a_gate_directory_is_refused_by_the_link_rule(tmp_path):
    (tmp_path / "docs" / "cache").mkdir(parents=True)
    os.symlink("docs/cache", tmp_path / "ci")
    assert es._gate_link(RECORD, str(tmp_path), "ci")


def test_a_link_is_classified_by_its_own_name_whatever_its_target(tmp_path):
    for rel in ("README.md", "docs/data.md", "docs/cache/x.md"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    os.symlink("cache", tmp_path / "docs" / "x.pyc")           # a link to a directory, named like bytecode
    os.symlink("data.md", tmp_path / "docs" / "y.pyc")         # a link to a file, named like bytecode
    os.symlink("cache", tmp_path / "docs" / "__pycache__")     # a link to a directory, named like a cache directory
    os.symlink("data.md", tmp_path / "docs" / "z_cache")       # an ordinary name
    listed = es.tree_paths(RECORD, tmp_path)
    assert "docs/x.pyc" not in listed and "docs/y.pyc" not in listed
    assert "docs/__pycache__" in listed and "docs/z_cache" in listed
    assert es.check_coverage(RECORD, tmp_path)["unclassified"] == []


@pytest.mark.parametrize("path", ["Docs/harnesses/x.md", "docs/Harnesses/x.md", "scripts/Evolution_Surface.py",
                                  "Conftest.py", "CI/x.py", "docs/Alpha-2/OWNER_OPERATED_VERIFIER.md",
                                  "architecture/Evolution-Surface-Authority.json"])
def test_a_case_variant_of_gate_material_falls_in_no_class(path):
    # F1 (owner Q-GOV-CAP): files and links alike, refused everywhere
    assert es.resolve(RECORD, path) is None
    assert es.pr_approvers(RECORD, [path]) is None and es.pr_activators(RECORD, [path]) is None
    with pytest.raises(es.Refused) as refusal:
        es.check_paths(RECORD, [path])
    assert refusal.value.code == "COVERAGE"


@pytest.mark.parametrize("link,target", [
    ("docs/Harnesses", "../task-packets/p"),
    ("architecture/Evolution-Surface-Authority.json", "../docs/data.md"),
    ("scripts/Evolution_Surface.py", "../docs/data.md"),
])
def test_a_link_at_a_case_variant_of_gate_material_is_refused(tmp_path, link, target):
    for rel in ("README.md", "docs/data.md", "task-packets/p/x.yaml"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    (tmp_path / link).parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target, tmp_path / link)
    assert es._gate_link(RECORD, str(tmp_path), link)
    with pytest.raises(es.Refused) as refusal:
        es.check_coverage(RECORD, tmp_path)
    assert refusal.value.code == "COVERAGE"


def test_an_entry_that_vanished_inside_a_skip_directory_is_absent(tmp_path, monkeypatch):
    # F2: a bytecode writer's renamed temporary file is absent; a vanished entry elsewhere still fails closed
    for rel in ("README.md", "ci/x.py", "ci/__pycache__/x.cpython-312.pyc.tmp", "docs/gone.md"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    real_lstat = os.lstat

    def vanishing(*names):
        def lstat(path, *args, **kwargs):
            if str(path).endswith(names):
                raise FileNotFoundError(2, "vanished", str(path))
            return real_lstat(path, *args, **kwargs)
        return lstat

    monkeypatch.setattr(es.os, "lstat", vanishing(".pyc.tmp", "gone.md"))
    with pytest.raises(es.Refused) as refusal:
        es.check_coverage(RECORD, tmp_path)
    assert refusal.value.code == "COVERAGE"
    monkeypatch.setattr(es.os, "lstat", real_lstat)
    (tmp_path / "docs" / "gone.md").unlink()
    monkeypatch.setattr(es.os, "lstat", vanishing(".pyc.tmp"))
    assert es.check_coverage(RECORD, tmp_path)["unclassified"] == []


@pytest.mark.parametrize("vanished,refused", [
    ("ci/__pycache__/sub", False),   # a directory that vanished inside a skip directory is absent (F2)
    ("ci/__pycache__", True),        # a skip directory that itself vanished is not inside one: fails closed (G1R5-1)
    ("docs/sub", True),              # a directory that vanished elsewhere fails closed
])
def test_the_directory_branch_of_f2(tmp_path, monkeypatch, vanished, refused):
    for rel in ("README.md", "ci/x.py", "ci/__pycache__/sub/x.pyc", "docs/sub/x.md"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    real_scandir = os.scandir

    def scandir(path="."):
        if str(path).replace(os.sep, "/").endswith(vanished):
            raise FileNotFoundError(2, "vanished", str(path))
        return real_scandir(path)

    monkeypatch.setattr(es.os, "scandir", scandir)
    if refused:
        with pytest.raises(es.Refused) as refusal:
            es.check_coverage(RECORD, tmp_path)
        assert refusal.value.code == "COVERAGE"
    else:
        assert es.check_coverage(RECORD, tmp_path)["unclassified"] == []


def test_an_empty_root_is_refused():
    # G1R5-2: an empty root no longer means the current directory
    for call in (es.check_coverage, es.tree_paths):
        with pytest.raises(es.Refused) as refusal:
            call(RECORD, "")
        assert refusal.value.code == "COVERAGE"


def test_the_root_is_resolved_as_the_file_system_resolves_it(tmp_path):
    # G1R5-2: '..' after a linked component means what the file system means, not what the spelling suggests
    (tmp_path / "x" / "sub").mkdir(parents=True)
    (tmp_path / "x" / "tree").mkdir()
    (tmp_path / "x" / "tree" / "README.md").write_text("x")
    os.symlink(tmp_path / "x" / "sub", tmp_path / "link")
    assert es.check_coverage(RECORD, str(tmp_path / "link") + "/../tree")["files"] == 1


@pytest.mark.parametrize("suffix", ["/", "/."])
def test_a_linked_root_is_refused_however_it_is_written(tmp_path, suffix):
    # F3: the root is normalized before the linked-root check
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "README.md").write_text("x")
    os.symlink(tmp_path / "real", tmp_path / "root")
    with pytest.raises(es.Refused) as refusal:
        es.check_coverage(RECORD, str(tmp_path / "root") + suffix)
    assert refusal.value.code == "COVERAGE"


def test_every_function_judges_the_record_first():
    broken = es.mutate(RECORD, [{"path": ["version"], "value": 0}])
    calls = (lambda: es.decide(broken, "programme", "OWNER", "GATE_CI", "approve"),
             lambda: es.resolve(broken, "ci/x.py"), lambda: es.pr_approvers(broken, ["ci/x.py"]),
             lambda: es.pr_activators(broken, ["ci/x.py"]), lambda: es.derive_gate_material(broken),
             lambda: es.coverage(broken, ["ci/x.py"]), lambda: es.skipped(broken, "ci/x.py"),
             lambda: es.check_paths(broken, ["ci/x.py"]))
    for call in calls:
        with pytest.raises(es.Refused) as refusal:
            call()
        assert refusal.value.code == "SHAPE"


def test_the_record_is_not_mutated_by_any_question():
    before = copy.deepcopy(RECORD)
    es.replay(RECORD, VECTORS)
    assert RECORD == before


def test_the_model_uses_the_standard_library_only():
    tree = ast.parse((ROOT / "scripts/evolution_surface.py").read_text(encoding="utf-8"))
    imported = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
                for alias in node.names}
    imported |= {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert imported <= {"__future__", "fnmatch", "hashlib", "json", "math", "os", "re", "stat", "pathlib"}


def test_the_vectors_name_their_grounds_and_keep_the_consumer_cases():
    assert all(row["grounds"] for row in VECTORS["decisions"])
    assert {row["grounds"] for row in VECTORS["consumerCases"]} >= {"E2E-10", "E2E-13", "E2E-14", "E2E-16", "P28"}
