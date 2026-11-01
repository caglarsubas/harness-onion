"""Exact source lineage for MET-ENFORCE-040; operator edge record v9: the head keeps the full fan-in (8 own and 67 predecessor routes, every catalog walk and round trip, the full payload loop), and the semantic check (the freeze, the files added, the adoption, edge record v9 and the canonical hunks) has a failing case for every refusal, each on plain data."""
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

from scripts import validate_edge_record_v9 as profile
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
    # The newer MET-GOV-001 layer is projected away before this layer's payload checks.
    return profile.successor.historical_catalog(packets())


def changed_test():
    return next(path for path in profile._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert profile.validate() is None
    current = packets()
    accepted = profile.historical_catalog(current)
    assert len(current) == 275 and len(accepted) == 255
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
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            *profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.PRODUCT_PACKETS}
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


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "ccomp_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = profile.historical_bytes(path, raw) if route in ("current_test", "old_bytes") else None
    current_packets = packets() if route == "catalog" else None
    layer = layer_packets() if route == "payloads" else None
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
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
    with pytest.raises(ValueError, match="edge record v9 history authority digest"):
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
    assert len(profile.historical_catalog(current)) == 255


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
    assert len(profile.historical_catalog(current)) == 255
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
    assert len(rules) == 256 and len(parsed) == 255
    assert profile._packet_rules() is rules and len(parsed) == 255
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
    with pytest.raises(ValueError, match="edge record v9 history authority digest"):
        profile.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = layer_packets()
    profile.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "edge-record-v9-authority.json").write_bytes(
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
    # The newer MET-GOV-001 layer refuses a mutated validator before this layer.
    with pytest.raises(ValueError, match="unreviewed current source: scripts/validate_edge_record_v9.py"):
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
            assert all("validate_" not in alias.name or alias.name == "validate_evolution_surface"
                       for alias in node.names)


def _count_authority_reads(monkeypatch):
    counts = {}
    for module in (profile.successor, profile, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner):
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
    expected = {module.__name__: 1 for module in (profile.successor, profile, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner)}
    if route == "current_test":
        # The forward route reads this layer's newest bytes and then projects them forward once more.
        assert all(counts[name] >= 1 for name in expected) and set(counts) == set(expected)
    else:
        assert counts == expected


# MET-ENFORCE-040 (EDGE-V9): this era's check, and a failing case for every check. Every mutant below is applied to plain
# data handed to the layer's pure checks: nothing in the layer or the library is patched or swapped.

VALIDATE = profile.validate_edge_record_v9
# Tamper values name packets, bases and files that already exist and that this record does not carry in the tampered
# place (edge record v7's packet, 253's merge, the I01 wire's validator), never a later packet id, so that no later
# packet's mechanics can turn a negative into a positive (the monitor's slot-253 catch).
OTHER_PACKET = "MET-ENFORCE-038"
OTHER_BASE = "585364b94e3e4a8bf1418ef750ce3d71cd38f95a"
OTHER_PATH = "scripts/validate_policy_observation.py"


def _load(path):
    return json.loads(profile.reviewed_bytes(path))


def _status():
    return _load(profile.STATUS_PATH)


def _records():
    return [_load(path) for path in profile.RECORDS]


def test_the_contract_holds_for_this_era():
    assert VALIDATE() is None


def test_every_added_file_record_and_predecessor_is_pinned():
    pinned = set(profile.ERA_SHA256)
    assert len(profile.NEW_FILES) == 5 and len(profile.FROZEN_PATHS) == 18 and len(pinned) == 23
    assert set(profile.NEW_FILES) | set(profile.FROZEN_PATHS) == pinned and not set(profile.NEW_FILES) & set(profile.FROZEN_PATHS)
    assert list(profile.FROZEN_EDGES) == [profile.EDGES_DIR + name for name in ["README.md"] + ["README-v%d.md" % n for n in range(2, 9)]
                                          + ["operator-harness-engineering.json"]
                                          + ["operator-harness-engineering-v%d.json" % n for n in range(2, 9)]]
    assert profile.V8_EDGE in profile.FROZEN_EDGES and set(profile.PROVIDERS) <= set(profile.FROZEN_PATHS)
    assert {row[0] for row in profile.NEW_ROWS} == set(profile.PROVIDERS)
    assert {row["record"] for row in _status()["rounds"]} == set(profile.RECORDS)
    for path, expected in profile.ERA_SHA256.items():
        assert profile.digest(profile.reviewed_bytes(path)) == expected


@pytest.mark.parametrize("path", sorted(profile.ERA_SHA256))
def test_every_era_file_is_bound_by_digest(path):
    raw = profile._verified(path)
    assert profile._era_bytes(path, raw) == raw
    for changed in (raw + b" ", bytearray(raw)):
        with pytest.raises(ValueError, match=re.escape("unreviewed EDGE-V9 source: " + path)):
            profile._era_bytes(path, changed)


def test_a_path_outside_the_era_is_refused_before_it_is_read():
    for path in ("architecture/edge-record-v9/notes.md", profile.EDGES_DIR + "README-v10.md", OTHER_PATH,
                 profile.VALIDATOR_PATH, None):
        with pytest.raises(ValueError, match="MET-ENFORCE-040 reviewed bytes are bound: "):
            profile._verified(path)
        with pytest.raises(ValueError, match="MET-ENFORCE-040 reviewed bytes are bound: "):
            profile._era_bytes(path, b"")


# The freeze and the files this packet adds -----------------------------------------------------------------------------

def _changed_and_added():
    return list(profile._PROJECTION_RULES), list(profile.authority()["newFiles"])


@pytest.mark.parametrize("path", profile.FROZEN_PATHS)
def test_the_predecessor_edge_records_and_providers_may_not_change(path):
    changed, added = _changed_and_added()
    profile.check_freeze(changed, added)
    for case in ((changed + [path], added), (changed, added + [path])):
        with pytest.raises(ValueError, match=re.escape("edge records v1 to v8, their READMEs and the two provider files "
                                                       "stay byte-identical")):
            profile.check_freeze(*case)


@pytest.mark.parametrize("path, where", [(profile.EDGES_DIR + "operator-harness-engineering-v10.json", "added"),
                                         (profile.EDGES_DIR + "README-v10.md", "added"),
                                         (profile.V9_README, "changed"), (profile.V9_EDGE, "changed")])
def test_only_v9s_two_files_are_added_under_the_edge_directory(path, where):
    changed, added = _changed_and_added()
    if where == "added":
        added = added + [path]
    else:
        changed = changed + [path]
    with pytest.raises(ValueError, match=re.escape("only v9's two files are added under architecture/artifact-edges/: "
                                                   + path)):
        profile.check_freeze(changed, added)


@pytest.mark.parametrize("change", ["missing", "extra", "changed", "edge_extra"])
def test_the_contract_files_and_records_are_new_each_once(change):
    changed, added = _changed_and_added()
    profile.check_new_files(added, changed)
    if change == "missing":
        added.remove(profile.STATUS_PATH)
    elif change == "extra":
        added.append(profile.RECORD_DIR + "/review-round3.json")
    elif change == "changed":
        changed.append(profile.RECORDS[0])
    else:
        added.append(profile.EDGES_DIR + "README-v10.md")
    with pytest.raises(ValueError, match="the contract's files and records are new in this packet, each once"):
        profile.check_new_files(added, changed)


@pytest.mark.parametrize("change, message", [
    ("extra", "the record directory holds exactly its three records, each of mode 100644"),
    ("missing", "the record directory holds exactly its three records, each of mode 100644"),
    ("executable", "the record directory holds exactly its three records, each of mode 100644"),
    ("link", "the record directory holds exactly its three records, each of mode 100644"),
    ("directory_link", "the record directory is a directory, not a link")])
def test_the_record_directory_is_closed_and_every_record_is_mode_100644(change, message):
    mode, tree = profile.reviewed_mode(profile.RECORD_DIR), profile.reviewed_tree(profile.RECORD_DIR)
    assert sorted(tree) == sorted(profile.RECORD_FILES) and stat.S_ISDIR(mode)
    profile.check_record_tree(mode, tree)
    tree = dict(tree)
    if change == "extra":
        tree[profile.RECORD_DIR + "/notes.md"] = stat.S_IFREG | 0o644
    elif change == "missing":
        del tree[profile.RECORDS[1]]
    elif change == "executable":
        tree[profile.STATUS_PATH] = stat.S_IFREG | 0o755
    elif change == "link":
        tree[profile.RECORDS[0]] = stat.S_IFLNK | 0o777
    else:
        mode = stat.S_IFLNK | 0o777
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.check_record_tree(mode, tree)


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
    # A list of the scanned-for patterns (as review round 2's hygiene check writes it) names no path.
    profile.check_added_file(path, mode, raw + b" /" + b"users/, /" + b"private/, .local" + b"/state, email pattern")


# The adoption -------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("change", ["schema", "work_item", "packet", "slot", "slot_type", "state", "base", "reviewer",
                                    "adopted_digest", "adopted_order", "builder", "builder_key", "non_claim",
                                    "extra_key", "missing_key", "key_order"])
def test_the_status_is_closed_and_records_the_adoption(change):
    status = _status()
    profile.check_status(status)
    if change == "schema":
        status["schemaVersion"] = "planeon.internal.edge-record-v8-status/v1"
    elif change == "work_item":
        status["workItem"] = "EDGE-V8"
    elif change == "packet":
        status["packet"] = OTHER_PACKET
    elif change == "slot":
        status["slot"] = 255
    elif change == "slot_type":
        status["slot"] = 256.0
    elif change == "state":
        status["status"] = "CONTRACT_CANDIDATE"
    elif change == "base":
        status["baseMain"] = OTHER_BASE
    elif change == "reviewer":
        status["independentReviewer"] = "AUTHOR"
    elif change == "adopted_digest":
        status["adoptedSubject"][profile.V9_README] = "0" * 64
    elif change == "adopted_order":
        status["adoptedSubject"] = dict(reversed(list(status["adoptedSubject"].items())))
    elif change == "builder":
        status["builder"]["sha256"] = status["rounds"][0]["builderSha256"]
    elif change == "builder_key":
        status["builder"]["note"] = "x"
    elif change == "non_claim":
        status["nonClaims"].pop()
    elif change == "extra_key":
        status["reviewBase"] = OTHER_BASE
    elif change == "missing_key":
        del status["builder"]
    else:
        status["workItem"] = status.pop("workItem")
    with pytest.raises(ValueError, match="adopted EDGE-V9 status"):
        profile.check_status(status)


@pytest.mark.parametrize("change", ["decision", "date", "decided_by", "extra_key", "key_order"])
def test_the_adoption_is_the_monitors_decision_verbatim(change):
    status = _status()
    adoption = status["adoption"]
    assert adoption == profile.ADOPTION and adoption["decision"].startswith(
        "[lane monitor] **ADOPTED**: EDGE-V9 candidate 2 as is (edge v9 197f30e4, README-v9 8cde7d19, builder 6573f4d0)")
    assert profile.ADOPTED_SHA256[profile.V9_EDGE].startswith("197f30e4")
    assert profile.ADOPTED_SHA256[profile.V9_README].startswith("8cde7d19") and profile.BUILDER["sha256"].startswith("6573f4d0")
    if change == "decision":
        adoption["decision"] = adoption["decision"].replace("candidate 2", "candidate 1")
    elif change == "date":
        adoption["date"] = "2026-10-21"
    elif change == "decided_by":
        adoption["decidedBy"] = "the author"
    elif change == "extra_key":
        adoption["note"] = "x"
    else:
        adoption["date"] = adoption.pop("date")
    with pytest.raises(ValueError, match="the adoption is the lane monitor's decision, verbatim"):
        profile.check_status(status)


@pytest.mark.parametrize("change", ["missing", "id", "ruling", "what", "extra", "key_order"])
def test_the_slip_record_is_present(change):
    status = _status()
    slips = status["slips"]
    assert [row["id"] for row in slips] == ["MON-256-LSTREE-SLIP"] and "exact path only" in slips[0]["what"]
    if change == "missing":
        slips.clear()
    elif change == "id":
        slips[0]["id"] = "MON-254-WALK"
    elif change == "ruling":
        slips[0]["ruling"] = "pending"
    elif change == "what":
        slips[0]["what"] = slips[0]["what"].replace("(0)", "(1)")
    elif change == "extra":
        slips.append(dict(slips[0]))
    else:
        slips[0]["id"] = slips[0].pop("id")
    with pytest.raises(ValueError, match="the slip record is present: MON-256-LSTREE-SLIP"):
        profile.check_status(status)


@pytest.mark.parametrize("path", profile.SUBJECT)
def test_the_contract_files_are_the_adopted_candidate_2(path):
    raw = profile._verified(path)
    profile.check_subject(path, raw)
    for changed in (raw + b"\n", raw.replace(b"\n", b"\r\n", 1), None):
        with pytest.raises(ValueError, match=re.escape("the contract files are the adopted candidate 2: " + path)):
            profile.check_subject(path, changed)


@pytest.mark.parametrize("change", ["reordered", "one_round", "last_verdict", "last_subject", "last_minor"])
def test_two_rounds_in_order_and_the_passing_round_left_notes_only(change):
    rounds = _status()["rounds"]
    profile.check_rounds(rounds)
    if change == "reordered":
        rounds.reverse()
    elif change == "one_round":
        rounds.pop(0)
    elif change == "last_verdict":
        rounds[-1]["verdict"] = "CHANGES_REQUIRED"
    elif change == "last_subject":
        rounds[-1]["subjectSha256"] = dict(profile.ROUND_SUBJECTS[1])
    else:
        rounds[-1]["severities"]["MINOR"] = 1
    with pytest.raises(ValueError, match="two review rounds in order; the passing round left NOTEs only"):
        profile.check_rounds(rounds)


ROUND_CHANGES = ["record_bytes", "record_digest", "record_path", "row_round", "row_verdict", "row_base", "row_builder",
                 "row_brief", "row_subject", "row_subject_order", "row_severities", "row_key", "subject_edge",
                 "subject_readme", "subject_builder", "subject_base", "subject_key", "record_verdict", "reviewer",
                 "actions", "finding_dropped", "finding_renamed", "record_key", "record_round"]


@pytest.mark.parametrize("number", [1, 2])
@pytest.mark.parametrize("change", ROUND_CHANGES)
def test_each_round_is_bound_to_its_record_and_its_subject(number, change):
    row = _status()["rounds"][number - 1]
    raw = profile._verified(profile.RECORDS[number - 1])
    record = json.loads(raw)
    profile.check_round(number, row, record, raw)
    subject = record["subject"]
    if change == "record_bytes":
        raw = raw + b"\n"
    elif change == "record_digest":
        row["recordSha256"] = "0" * 64
    elif change == "record_path":
        row["record"] = profile.RECORDS[2 - number]
    elif change == "row_round":
        row["round"] = 3 - number
    elif change == "row_verdict":
        row["verdict"] = "PASS" if number == 1 else "CHANGES_REQUIRED"
    elif change == "row_base":
        row["base"] = OTHER_BASE
    elif change == "row_builder":
        row["builderSha256"] = "0" * 64
    elif change == "row_brief":
        row["briefSha256"] = "0" * 64
    elif change == "row_subject":
        row["subjectSha256"][profile.V9_EDGE] = "0" * 64
    elif change == "row_subject_order":
        row["subjectSha256"] = dict(reversed(list(row["subjectSha256"].items())))
    elif change == "row_severities":
        row["severities"]["NOTE"] += 1
    elif change == "row_key":
        row["snapshot"] = "x"
    elif change == "subject_edge":
        subject["edgeV9Sha256"] = "0" * 64
    elif change == "subject_readme":
        subject["readmeV9Sha256"] = "0" * 64
    elif change == "subject_builder":
        subject["builderSha256"] = "0" * 64
    elif change == "subject_base":
        subject["base"] = OTHER_BASE
    elif change == "subject_key":
        subject["edgeV9Sha256"] = subject.pop("edgeV9Sha256")
    elif change == "record_verdict":
        record["verdict"] = "PASS_FOR_ADOPTION" if number == 1 else "CHANGES_REQUIRED"
    elif change == "reviewer":
        record["reviewer"] = "the author"
    elif change == "actions":
        record["actions"]["edgeDirListed"] = True
    elif change == "finding_dropped":
        record["findings"].pop()
    elif change == "finding_renamed":
        record["findings"][0]["id"] = "E3-1"
    elif change == "record_key":
        record["notes"] = []
    else:
        record["round"] = 3
    with pytest.raises(ValueError, match=re.escape("review round %d is bound to its record and its subject" % number)):
        profile.check_round(number, row, record, raw)


@pytest.mark.parametrize("change", ["value", "order", "missing", "resolution_status", "resolution_missing",
                                    "resolution_renamed", "evidence", "resolution_key"])
def test_the_closed_findings_are_round_2s_resolutions(change):
    status, records = _status(), _records()
    profile.check_findings(status, records)
    resolutions = records[1]["round1Resolutions"]
    if change == "value":
        status["closedFindings"]["E1-2"] = "CARRIED to the packet review"
    elif change == "order":
        status["closedFindings"] = dict(reversed(list(status["closedFindings"].items())))
    elif change == "missing":
        del status["closedFindings"]["E1-5"]
    elif change == "resolution_status":
        resolutions[1]["status"] = "CARRIED"
    elif change == "resolution_missing":
        resolutions.pop()
    elif change == "resolution_renamed":
        resolutions[0]["id"] = "E1-9"
    elif change == "evidence":
        resolutions[2]["evidence"] = " "
    else:
        resolutions[3]["note"] = "x"
    with pytest.raises(ValueError, match="the closed findings are round 2's resolutions"):
        profile.check_findings(status, records)


@pytest.mark.parametrize("change", ["item", "to", "action", "dropped", "extra", "key_order"])
def test_the_carried_rows_are_round_2s_notes_and_the_identity_rules_carry(change):
    status, records = _status(), _records()
    carried = status["carried"]
    assert [row["item"].split(" ")[0] for row in carried[:2]] == ["E2-1", "E2-2"] and "identity rule" in carried[2]["item"]
    if change == "item":
        carried[0]["item"] = "E2-3 (contract review round 2, NOTE)"
    elif change == "to":
        carried[2]["to"] = "the packet review"
    elif change == "action":
        carried[1]["action"] = ""
    elif change == "dropped":
        carried.pop()
    elif change == "extra":
        carried.append(dict(carried[0]))
    else:
        carried[0]["item"] = carried[0].pop("item")
    with pytest.raises(ValueError, match="the carried rows are round 2's notes and the identity rule's carry"):
        profile.check_findings(status, records)


# Edge record v9 -------------------------------------------------------------------------------------------------------

def _edge():
    v8_raw = profile._verified(profile.V8_EDGE)
    providers = {path: (profile._verified(path), profile.reviewed_mode(path)) for path in profile.PROVIDERS}
    return json.loads(v8_raw), _load(profile.V9_EDGE), v8_raw, providers


def _mutate_edge(v8, value, change):
    rows = value["artifacts"]
    if change == "v8_row_changed":
        rows[0]["mode"] = "100755" if rows[0]["mode"] == "100644" else "100644"
    elif change == "v8_rows_reordered":
        rows[0], rows[1] = rows[1], rows[0]
    elif change == "v8_row_dropped":
        del rows[5]
    elif change == "v8_row_key_order":
        rows[2] = dict(reversed(list(rows[2].items())))
    elif change == "extra_row":
        rows.append(dict(rows[-1], providerPath=OTHER_PATH))
    elif change == "new_sha":
        rows[66]["sha256"] = "0" * 64
    elif change == "new_commit":
        rows[67]["providerCommit"] = "0" * 40
    elif change == "new_commit_null":
        rows[66]["providerCommit"] = None
    elif change == "new_packet":
        rows[66]["providerPacket"] = OTHER_PACKET
    elif change == "new_mode":
        rows[67]["mode"] = "100755"
    elif change == "new_path":
        rows[66]["providerPath"] = OTHER_PATH
    elif change == "new_consumer":
        rows[67]["consumerPath"] = rows[67]["consumerPath"].replace("contracts/i01-v1/", "contracts/")
    elif change == "new_consumer_name":
        rows[66]["consumerPath"] = rows[66]["consumerPath"].replace("channel.schema.json", "schema.json")
    elif change == "new_status":
        rows[66]["status"] = "IN_USE"
    elif change == "new_relation":
        rows[67]["relation"] = "DERIVED"
    elif change == "new_consumer_packet":
        rows[66]["consumerPacket"] = "HE-004D2"
    elif change == "new_key_order":
        rows[67] = dict(reversed(list(rows[67].items())))
    elif change == "supersedes_digest":
        value["supersedes"]["sha256"] = "sha256:" + "0" * 64
    elif change == "supersedes_packet":
        value["supersedes"]["packet"] = OTHER_PACKET
    elif change == "supersedes_path":
        value["supersedes"]["path"] = profile.EDGES_DIR + "operator-harness-engineering-v7.json"
    elif change == "supersedes_order":
        value["supersedes"] = dict(reversed(list(value["supersedes"].items())))
    elif change == "schema":
        value["schemaVersion"] = "planeon.internal.artifact-edge-registry/v3"
    elif change == "rules":
        value["rules"].append("A consumer may hold another version.")
    elif change == "owner_decision":
        value["ownerDecision"] = str(value["ownerDecision"]) + " (changed)"
    elif change == "not_artifacts":
        value["notArtifacts"].append(OTHER_PATH)
    elif change == "statuses":
        value["statuses"] = {"IN_USE": "changed"}
    elif change == "graph":
        value["graph"] = "changed"
    elif change == "artifact":
        value["artifact"] = "i06-backend-profile-v4-observer-rbac"
    elif change == "notes":
        value["notes"] = []
    elif change == "owner_decisions":
        value["ownerDecisions"] = [" "]
    elif change == "decisions_reordered":
        decisions = value["ownerDecisions"]
        decisions[2], decisions[3] = decisions[3], decisions[2]
    elif change == "decision_dropped":
        value["ownerDecisions"].pop()
    elif change == "key_order":
        value["graph"] = value.pop("graph")
    elif change == "v8_key_order":
        v8["graph"] = v8.pop("graph")
    else:
        raise AssertionError(change)


EDGE_CHANGES = [
    ("v8_row_changed", "edge record v9 carries v8's 66 rows exactly and in order"),
    ("v8_rows_reordered", "edge record v9 carries v8's 66 rows exactly and in order"),
    ("v8_row_dropped", "edge record v9 carries v8's 66 rows exactly and in order"),
    ("v8_row_key_order", "edge record v9 carries v8's 66 rows exactly and in order"),
    ("extra_row", "edge record v9 carries v8's 66 rows exactly and in order"),
    ("new_sha", "edge record v9 row 67 registers"), ("new_commit", "edge record v9 row 68 registers"),
    ("new_commit_null", "edge record v9 row 67 registers"), ("new_packet", "edge record v9 row 67 registers"),
    ("new_mode", "edge record v9 row 68 registers"), ("new_path", "edge record v9 row 67 registers"),
    ("new_consumer", "edge record v9 row 68 registers"), ("new_consumer_name", "edge record v9 row 67 registers"),
    ("new_status", "edge record v9 row 67 registers"), ("new_relation", "edge record v9 row 68 registers"),
    ("new_consumer_packet", "edge record v9 row 67 registers"), ("new_key_order", "edge record v9 row 68 registers"),
    ("supersedes_digest", "edge record v9 supersedes v8 by its digest and packet"),
    ("supersedes_packet", "edge record v9 supersedes v8 by its digest and packet"),
    ("supersedes_path", "edge record v9 supersedes v8 by its digest and packet"),
    ("supersedes_order", "edge record v9 supersedes v8 by its digest and packet"),
    ("schema", "edge record v9 supersedes v8 by its digest and packet"),
    ("rules", "edge record v9 supersedes v8 by its digest and packet"),
    ("owner_decision", "edge record v9 supersedes v8 by its digest and packet"),
    ("not_artifacts", "edge record v9 supersedes v8 by its digest and packet"),
    ("statuses", "edge record v9 supersedes v8 by its digest and packet"),
    ("graph", "edge record v9 supersedes v8 by its digest and packet"),
    ("artifact", "edge record v9 supersedes v8 by its digest and packet"),
    ("notes", "edge record v9 supersedes v8 by its digest and packet"),
    ("owner_decisions", "edge record v9 supersedes v8 by its digest and packet"),
    ("decisions_reordered", "edge record v9 supersedes v8 by its digest and packet"),
    ("decision_dropped", "edge record v9 supersedes v8 by its digest and packet"),
    ("key_order", "edge record v9 supersedes v8 by its digest and packet"),
    ("v8_key_order", "edge record v9 supersedes v8 by its digest and packet")]


@pytest.mark.parametrize("change, message", EDGE_CHANGES, ids=[row[0] for row in EDGE_CHANGES])
def test_every_edge_record_rule_is_checked(change, message):
    v8, v9, v8_raw, providers = _edge()
    profile.check_edge_record(v8, v9, v8_raw, providers)
    _mutate_edge(v8, v9, change)
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.check_edge_record(v8, v9, v8_raw, providers)


def test_edge_record_v8_is_the_one_v9_supersedes():
    v8, v9, v8_raw, providers = _edge()
    for changed in (v8_raw + b"\n", None):
        with pytest.raises(ValueError, match="edge record v9 supersedes v8 by its digest and packet"):
            profile.check_edge_record(v8, v9, changed, providers)


@pytest.mark.parametrize("number", [67, 68])
@pytest.mark.parametrize("change", ["bytes", "executable", "link", "missing"])
def test_a_changed_provider_file_or_mode_is_refused(number, change):
    v8, v9, v8_raw, providers = _edge()
    path = profile.NEW_ROWS[number - 67][0]
    raw, mode = providers[path]
    if change == "bytes":
        providers[path] = (raw + b"\n", mode)
    elif change == "executable":
        providers[path] = (raw, stat.S_IFREG | 0o755)
    elif change == "link":
        providers[path] = (raw, stat.S_IFLNK | 0o777)
    else:
        del providers[path]
    with pytest.raises(ValueError, match=re.escape("edge record v9 row %d registers its provider's exact bytes and mode "
                                                   "before use: %s" % (number, path))):
        profile.check_edge_record(v8, v9, v8_raw, providers)


@pytest.mark.parametrize("change", ["consumer", "provider", "old_consumer"])
def test_each_provider_and_consumer_is_registered_once(change):
    v8, v9, _, _ = _edge()
    profile.check_registered_once(v8, v9)
    rows = v9["artifacts"]
    if change == "consumer":
        rows[67]["consumerPath"] = rows[66]["consumerPath"]
    elif change == "provider":
        rows[67]["providerPath"] = rows[3]["providerPath"]
    else:
        rows[66]["consumerPath"] = rows[10]["consumerPath"]
    with pytest.raises(ValueError, match="each provider path, and each new consumer path, is registered once"):
        profile.check_registered_once(v8, v9)


def test_the_new_rows_are_restated():
    rows = _load(profile.V9_EDGE)["artifacts"][profile.V8_ROWS:]
    assert [(row["providerPath"], row["providerCommit"], row["consumerPath"], row["consumerPacket"]) for row in rows] == [
        tuple(row) for row in profile.NEW_ROWS]
    assert list(profile.PROVIDERS) == ["architecture/policy-observation-inputs/channel.schema.json",
                                       "architecture/policy-observation-inputs/vectors.json"]
    assert [row[2] for row in profile.NEW_ROWS] == ["host-enforcement/contracts/i01-v1/channel.schema.json",
                                                    "host-enforcement/contracts/i01-v1/vectors.json"]
    assert {row[1] for row in profile.NEW_ROWS} == {profile.PROVIDER_COMMIT} and len(profile.PROVIDER_COMMIT) == 40
    assert {row[3] for row in profile.NEW_ROWS} == {"HE-004-I01"} and all("providerPacket" not in row for row in rows)
    assert [row["sha256"][:8] for row in rows] == ["fb69b772", "1bfb4677"]
    assert profile.V8_PACKET == "MET-ENFORCE-039" and profile.PREVIOUS_PACKET == "MET-PERF-042"
    assert profile.EDGE_V8_SHA256.startswith("623cf10b") and len(profile.DECISION_OPENINGS) == 8


# Reads and the canonical hunks -----------------------------------------------------------------------------------------

SEMANTIC_FUNCTIONS = {"_era_bytes", "_verified", "_json", "_holds", "_bound", "_git_mode", "_texts", "_local_path",
                      "check_freeze",
                      "check_new_files", "check_record_tree", "check_added_file", "validate_files", "check_status",
                      "check_subject", "check_rounds", "check_round", "check_findings", "validate_adoption",
                      "check_edge_record", "check_registered_once", "validate_edge_record", "validate_edge_record_v9"}


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
    "MET-ENFORCE-040 reviewed bytes are bound: ": "test_a_path_outside_the_era_is_refused_before_it_is_read",
    "unreviewed EDGE-V9 source: ": "test_every_era_file_is_bound_by_digest",
    "edge records v1 to v8, their READMEs and the two provider files stay byte-identical, and only v9's two files are "
    "added under architecture/artifact-edges/: ": "test_the_predecessor_edge_records_and_providers_may_not_change",
    "the contract's files and records are new in this packet, each once":
        "test_the_contract_files_and_records_are_new_each_once",
    "the record directory is a directory, not a link": "test_the_record_directory_is_closed_and_every_record_is_mode_100644",
    "the record directory holds exactly its three records, each of mode 100644":
        "test_the_record_directory_is_closed_and_every_record_is_mode_100644",
    "a file this packet adds is a regular file of git mode 100644: ":
        "test_an_added_file_is_a_regular_file_of_mode_100644_without_a_local_path",
    "no absolute local path in a file this packet adds: ":
        "test_an_added_file_is_a_regular_file_of_mode_100644_without_a_local_path",
    "adopted EDGE-V9 status": "test_the_status_is_closed_and_records_the_adoption",
    "the adoption is the lane monitor's decision, verbatim": "test_the_adoption_is_the_monitors_decision_verbatim",
    "the slip record is present: MON-256-LSTREE-SLIP": "test_the_slip_record_is_present",
    "the contract files are the adopted candidate 2: ": "test_the_contract_files_are_the_adopted_candidate_2",
    "two review rounds in order; the passing round left NOTEs only and reviewed the adopted candidate 2":
        "test_two_rounds_in_order_and_the_passing_round_left_notes_only",
    "review round ": "test_each_round_is_bound_to_its_record_and_its_subject",
    "the closed findings are round 2's resolutions": "test_the_closed_findings_are_round_2s_resolutions",
    "the carried rows are round 2's notes and the identity rule's carry, each with its action":
        "test_the_carried_rows_are_round_2s_notes_and_the_identity_rules_carry",
    "edge record v9 supersedes v8 by its digest and packet and keeps v8's decision, rules, exclusions, statuses and key "
    "order": "test_every_edge_record_rule_is_checked",
    "edge record v9 carries v8's 66 rows exactly and in order": "test_every_edge_record_rule_is_checked",
    "edge record v9 row ": "test_a_changed_provider_file_or_mode_is_refused",
    "each provider path, and each new consumer path, is registered once":
        "test_each_provider_and_consumer_is_registered_once",
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
        assert message[:40] in source or any(message.startswith(text) for text in _messages_of(name)), message


def _messages_of(name):
    """The expected messages a parametrized test lists in its parametrize marks."""
    rows = []
    for mark in getattr(globals()[name], "pytestmark", []):
        values = mark.args[1] if len(mark.args) > 1 else []
        for row in values:
            rows += [value for value in (row if isinstance(row, tuple) else (row,)) if isinstance(value, str)]
    return rows
