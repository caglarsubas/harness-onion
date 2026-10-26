"""Exact source lineage for MET-PERF-042; chain compaction: the head keeps the full fan-in (8 own and 66 predecessor routes, every catalog walk and round trip, the full payload loop), the identity rule holds on this era and on the live tree (items 1-8 by the reference model, item 9 on the imported modules), every identity-only fault is refused as source text, and the C2 shapes, fact map and records are checked in the validator."""
import ast
import functools
import hashlib
import importlib
import json
import copy
from copy import deepcopy
import os
import re
import stat
import sys
import types
from pathlib import Path
from types import MappingProxyType

import pytest

from scripts import validate_chain_compaction as profile
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
from scripts import chain_identity as identity


def packets():
    return {path.stem: safe_load(path.read_bytes())
            for path in (profile.ROOT / "task-packets").glob("*.yaml")}


def layer_packets():
    # The newer MET-ENFORCE-040 layer is projected away before this layer's payload checks.
    return profile.successor.historical_catalog(packets())


def changed_test():
    return next(path for path in profile._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert profile.validate() is None
    current = packets()
    accepted = profile.historical_catalog(current)
    assert len(current) == 268 and len(accepted) == 254
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
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET}
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


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "i6v4_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = profile.historical_bytes(path, raw) if route in ("current_test", "old_bytes") else None
    current_packets = packets() if route == "catalog" else None
    layer = layer_packets() if route == "payloads" else None
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
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
    with pytest.raises(ValueError, match="chain compaction history authority digest"):
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
    assert len(profile.historical_catalog(current)) == 254


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
    assert len(profile.historical_catalog(current)) == 254
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
    assert len(rules) == 255 and len(parsed) == 254
    assert profile._packet_rules() is rules and len(parsed) == 254
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
    with pytest.raises(ValueError, match="chain compaction history authority digest"):
        profile.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = layer_packets()
    profile.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "chain-compaction-authority.json").write_bytes(
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
    # The newer MET-ENFORCE-040 layer refuses a mutated validator before this layer.
    with pytest.raises(ValueError, match="unreviewed current source: scripts/validate_chain_compaction.py"):
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
            assert all("validate_" not in alias.name or alias.name == "validate_edge_record_v9"
                       for alias in node.names)


def _count_authority_reads(monkeypatch):
    counts = {}
    for module in (profile.successor, profile, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner):
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
    expected = {module.__name__: 1 for module in (profile.successor, profile, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner)}
    if route == "current_test":
        # The forward route reads this layer's newest bytes and then projects them forward once more.
        assert all(counts[name] >= 1 for name in expected) and set(counts) == set(expected)
    else:
        assert counts == expected


# MET-PERF-042 (CHAIN-COMPACTION-001): this era's check, the identity rule on the live tree, and every check's failing case.

_MISSING = object()
_CACHE = {}


def _rule():
    if "rule" not in _CACHE:
        _CACHE["rule"] = json.loads(profile._verified(profile.IDENTITY_RULE))
    return _CACHE["rule"]


def _modules():
    rows = {row["slot"]: row["module"] for row in _rule()["chain"]["layers"]}
    rows[255] = profile.HEAD_MODULE
    return rows


def _era_text(slot):
    key = ("era", slot)
    if key not in _CACHE:
        _CACHE[key] = profile._era_source(identity.validator_path(_modules()[slot])).decode("utf-8")
    return _CACHE[key]


def _previous_text(slot):
    path = identity.validator_path(_modules()[slot])
    return profile._undo_this_layer(path, _era_text(slot).encode("utf-8")).decode("utf-8")


def _era_chain():
    if "chain" not in _CACHE:
        _CACHE["chain"] = identity.walk_layers(profile._era_source, _rule())
    return _CACHE["chain"]


def _shapes():
    if "shapes" not in _CACHE:
        _CACHE["shapes"] = identity.loader_shapes(_rule(), {slot: tree for slot, _, _, tree in _era_chain()})
    return _CACHE["shapes"]


def _era_previous(path, raw):
    """The previous era of an era file, whatever bytes a faulted reader serves for it."""
    return profile._undo_this_layer(path, profile._era_source(path))


def _reader(served):
    return lambda path: served[path] if path in served else profile._era_source(path)


# This era's reads and records ------------------------------------------------------------------------------------------

def test_a_path_outside_the_era_is_refused_before_it_is_read():
    for path in ("scripts/unreviewed.py", profile.VALIDATOR_PATH, None):
        with pytest.raises(ValueError, match="MET-PERF-042 reviewed bytes are bound: "):
            profile._verified(path)
        with pytest.raises(ValueError, match="MET-PERF-042 reviewed bytes are bound: "):
            profile._era_bytes(path, b"")


@pytest.mark.parametrize("path", [profile.MODEL, profile.IDENTITY_RULE, profile.CONFTEST, "scripts/validate_unified_roadmap.py",
                                  "tests/test_linux_runner_contract.py", profile.HEAD_TEST])
def test_every_era_file_is_bound_by_digest(path):
    raw = profile._verified(path)
    assert profile._era_bytes(path, raw) == raw
    for changed in (raw + b" ", bytearray(raw)):
        with pytest.raises(ValueError, match=re.escape("unreviewed CHAIN-COMPACTION source: " + path)):
            profile._era_bytes(path, changed)


def test_the_heads_own_bytes_are_bound_by_the_authority():
    raw = profile._own_bytes()
    assert profile._era_source(profile.VALIDATOR_PATH) == raw
    for changed in (raw + b"\n# unreviewed\n", bytearray(raw), raw.replace(b"AUTHORITY_SHA256 = ", b"AUTHORITY_SHA256  = ", 1)):
        with pytest.raises(ValueError, match="the head's own bytes are its reviewed bytes"):
            profile._head_bytes(changed)


def test_the_model_and_the_rule_are_this_eras_bytes_on_the_live_tree():
    for path in (profile.MODEL, profile.IDENTITY_RULE):
        assert hashlib.sha256(profile.regular_bytes(path)).hexdigest() == profile.ERA_SHA256[path]
    assert Path(identity.__file__).resolve() == (profile.ROOT / profile.MODEL).resolve()


def test_the_era_table_is_this_eras_whole_input():
    expected = {identity.validator_path(module) for slot, module in _modules().items() if slot != 255}
    expected |= {identity.test_path(module) for slot, module in _modules().items() if slot >= 192}
    expected |= {profile.CONFTEST, profile.MODEL} | set(profile.RECORDS)
    assert set(profile.ERA_SHA256) == expected and len(expected) == 139


@pytest.mark.parametrize("change", ["extra", "missing", "mode"])
def test_the_records_directory_is_closed(change):
    tree = profile.reviewed_tree(profile.RECORD_DIR)
    profile.check_records_tree(tree)
    if change == "extra":
        tree[profile.RECORD_DIR + "/unreviewed.json"] = 0o100644
    elif change == "missing":
        tree.pop(profile.FACT_MAP)
    else:
        tree[profile.README] = 0o100755
    with pytest.raises(ValueError, match="the records directory holds exactly its seven records, each of mode 100644"):
        profile.check_records_tree(tree)


@pytest.mark.parametrize("path", [profile.README, profile.COST_REPORT, profile.DECISIONS, profile.AB, profile.SEEDED_FAULTS])
def test_no_record_may_carry_an_absolute_local_path(path):
    raw = profile._verified(path)
    profile.check_record_bytes(path, raw)
    marker = b"/" + b"Users/" + b"someone"
    with pytest.raises(ValueError, match=re.escape("no absolute local path in a record: " + path)):
        profile.check_record_bytes(path, raw + marker)


@pytest.mark.parametrize("change", ["extra_key", "missing_key", "not_a_mapping"])
def test_the_cost_report_is_m1s(change):
    value = json.loads(profile._verified(profile.COST_REPORT))
    profile.check_cost_report(value)
    if change == "extra_key":
        value["ab"] = {}
    elif change == "missing_key":
        value.pop(sorted(value)[0])
    else:
        value = [value]
    with pytest.raises(ValueError, match="the cost report is M1's, with its keys"):
        profile.check_cost_report(value)


@pytest.mark.parametrize("change", ["ab", "faults", "inherited_edit", "not_in_build"])
def test_the_readme_describes_both_measured_records(change):
    text = profile._verified(profile.README).decode("utf-8")
    profile.check_readme(text)
    if change == "not_in_build":
        changed = text + "\n## Not in this build\n"
    else:
        word = {"ab": "ab.json", "faults": "seeded-faults.json", "inherited_edit": "Q-CC-F1"}[change]
        changed = text.replace(word, "x")
    with pytest.raises(ValueError,
                       match="the README describes both measured records and the one inherited edit outside C2"):
        profile.check_readme(changed)


def _ab():
    return json.loads(profile._verified(profile.AB))


def _seeded():
    return json.loads(profile._verified(profile.SEEDED_FAULTS))


@pytest.mark.parametrize("change", ["extra_key", "missing_key", "mode", "measured_head"])
def test_the_ab_record_has_its_closed_shape(change):
    value = _ab()
    profile.check_ab(value)
    if change == "extra_key":
        value["unreviewed"] = True
    elif change == "missing_key":
        value.pop("B5")
    elif change == "mode":
        value["mode"] = "FULL"
    else:
        value["subject"]["measuredHead"]["commit"] = "b5867e91"
    with pytest.raises(ValueError, match=re.escape("the A/B record's closed shape")):
        profile.check_ab(value)


@pytest.mark.parametrize("change", ["b3_head", "collected_head", "b1_ratio", "b1_files", "b2_cpu", "b2_nodes"])
def test_the_ab_record_numbers_are_consistent(change):
    value = _ab()
    assert (value["collected"]["base"], value["collected"]["head"]) == (16560, 14916) and value["B1"]["ratio"] == 0.8187
    if change == "b3_head":
        value["B3"]["head"] += 1
    elif change == "collected_head":
        value["collected"]["head"] -= 1
    elif change == "b1_ratio":
        value["B1"]["ratio"] = 0.88
    elif change == "b1_files":
        value["B1"]["files"] = 140
    elif change == "b2_cpu":
        value["B2"]["cpu"] = value["B2"]["bound"] + 1
    else:
        value["B2"]["nodes"] = 701
    with pytest.raises(ValueError, match=re.escape("the A/B record's numbers are consistent")):
        profile.check_ab(value)


@pytest.mark.parametrize("change", ["decision", "words", "accepted", "b4_status"])
def test_the_ab_record_carries_the_owners_acceptance(change):
    value = _ab()
    assert value["ownerAcceptance"]["decision"] == "Accept and continue (Recommended)"
    if change == "decision":
        value["ownerAcceptance"]["decision"] = "Accept and continue"
    elif change == "words":
        value["ownerAcceptance"]["words"] = "Accepted."
    elif change == "accepted":
        value["ownerAcceptance"]["accepted"] = ["B1"]
    else:
        value["B4"]["status"] = "met"
    with pytest.raises(ValueError, match=re.escape("the A/B record carries the owner's acceptance verbatim")):
        profile.check_ab(value)


@pytest.mark.parametrize("change", ["extra_key", "missing_key"])
def test_the_seeded_faults_record_has_its_closed_shape(change):
    value = _seeded()
    profile.check_seeded_faults(value)
    if change == "extra_key":
        value["unreviewed"] = True
    else:
        value.pop("benign")
    with pytest.raises(ValueError, match=re.escape("the seeded-faults record's closed shape")):
        profile.check_seeded_faults(value)


@pytest.mark.parametrize("change", ["class_cases", "class_run", "scope_sum", "out_of_scope_class", "a_fail"])
def test_the_seeded_faults_numbers_are_consistent(change):
    value = _seeded()
    counts, classes = value["counts"], value["partI"]["classes"]
    assert (counts["total"], counts["run"], counts["outOfScope"]) == (559, 352, 207)
    if change == "class_cases":
        classes["R2"]["cases"] += 1
    elif change == "class_run":
        classes["R6"]["run"] -= 1
    elif change == "scope_sum":
        counts["outOfScope"] = 206
    elif change == "out_of_scope_class":
        counts["outOfScopeByClass"]["R4"] = 8
    else:
        classes["R7"]["fail"] = 1
    with pytest.raises(ValueError, match=re.escape("the seeded-faults record's numbers are consistent")):
        profile.check_seeded_faults(value)


@pytest.mark.parametrize("change", ["extra", "missing", "rc", "reports", "label", "refusal", "class_count"])
def test_the_six_collection_kills_are_exactly_the_ruled_cases(change):
    value = _seeded()
    kills = value["collectionKills"]
    assert [row["case"] for row in kills] == list(profile.COLLECTION_KILLS)
    if change == "extra":
        kills.append(dict(kills[0], case="R10-MAX-192"))
    elif change == "missing":
        kills.pop()
    elif change == "rc":
        kills[0]["rc"] = {"base": 4, "head": 1}
    elif change == "reports":
        kills[1]["nodeReports"] = {"base": 0, "head": 3}
    elif change == "label":
        kills[2]["harnessRawLabel"] = "PASS"
    elif change == "refusal":
        kills[3]["refusal"] = "source changed during read (ValueError)"
    else:
        # One kill counted as a pass instead: the class still sums, but it no longer holds six collection kills.
        value["partI"]["classes"]["R10"]["collectionKilled"] = 5
        value["partI"]["classes"]["R10"]["pass"] += 1
    with pytest.raises(ValueError, match=re.escape("the six collection kills are exactly the ruled cases")):
        profile.check_seeded_faults(value)


@pytest.mark.parametrize("change", ["scope", "scope_words", "ruling", "final", "ruling_words"])
def test_the_seeded_faults_record_carries_the_owners_scope_and_the_ruling(change):
    value = _seeded()
    if change == "scope":
        value["scope"]["decision"] = "Run 352"
    elif change == "scope_words":
        value["scope"]["words"] = "M3 scope: run 352."
    elif change == "ruling":
        value["partI"]["verdict"]["ruling"] = "MON-M3"
    elif change == "final":
        value["partI"]["verdict"]["final"] = "FAIL"
    else:
        value["partI"]["words"] = "Ruling: accepted."
    with pytest.raises(ValueError,
                       match=re.escape("the seeded-faults record carries the owner's scope and the monitor's ruling verbatim")):
        profile.check_seeded_faults(value)


@pytest.mark.parametrize("change", ["missing", "twice"])
def test_the_decisions_are_recorded_each_section_once(change):
    text = profile._verified(profile.DECISIONS).decode("utf-8")
    profile.check_decisions(text)
    header = profile.DECISION_HEADERS[-1]
    changed = text.replace(header, "## dropped") if change == "missing" else text + "\n" + header + "\n"
    with pytest.raises(ValueError, match="the decisions are recorded verbatim, each section once"):
        profile.check_decisions(changed)


@pytest.mark.parametrize("change", ["schema", "count", "discrepancy", "one_class", "key"])
def test_the_identity_rule_is_the_frozen_record(change):
    rule = copy.deepcopy(_rule())
    profile.check_identity_rule(rule)
    if change == "schema":
        rule["schemaVersion"] += "x"
    elif change == "count":
        rule["counts"]["attributeNames"] += 1
    elif change == "discrepancy":
        rule["discrepancies"] = ["unreviewed"]
    elif change == "one_class":
        rule["d"]["bridgedClasses"]["historical_bytes"] = [{"first": 192, "last": "head-1"}]
    else:
        rule["unreviewed"] = True
    with pytest.raises(ValueError, match="the identity rule is the frozen record"):
        profile.check_identity_rule(rule)


@pytest.mark.parametrize("key, value", [("layers", 66), ("head", 254), ("headModule", "validate_unreviewed"),
                                        ("newPacket", "MET-ENFORCE-039")])
def test_the_identity_rule_ran_over_the_whole_chain(key, value):
    summary = {"layers": profile.CHAIN_LAYERS, "head": 255, "headModule": profile.HEAD_MODULE,
               "newPacket": profile.NEW_PACKET}
    profile.check_summary(summary, 255)
    with pytest.raises(ValueError, match="the identity rule ran over this era's whole chain"):
        profile.check_summary(dict(summary, **{key: value}), 255)


def test_the_fact_map_totals_are_restated():
    totals = dict(profile.FACT_TOTALS)
    assert totals["droppedRouteNodes"] == 2079 and totals["adjacentKept"] == 63 and totals["functionNamesLost"] == 0
    profile.check_totals(totals)
    with pytest.raises(ValueError, match="the fact map's totals"):
        profile.check_totals(dict(totals, droppedRouteNodes=2078))


# The identity rule on the live tree (both in NEVER_SHARED: no sharing wrapper is installed while they run) ----------

def test_identity_rule_holds_on_the_live_chain():
    """Items 1-8 over the live tree, on every verify: the live head's one-step projection gives each layer's previous
    era. From slot 256 on this is a predecessor test, so the rule binds every later packet."""
    rule = _rule()
    for path in (profile.MODEL, profile.IDENTITY_RULE):
        assert hashlib.sha256(profile.regular_bytes(path)).hexdigest() == profile.ERA_SHA256[path]
    chain = identity.walk_layers(profile.regular_bytes, rule)
    head = importlib.import_module("scripts." + chain[-1][1])
    count = len(list((profile.ROOT / "task-packets").glob("*.yaml")))
    summary = identity.check(profile.regular_bytes, head.historical_bytes, rule, count)
    assert summary["layers"] == count - 188 and summary["head"] == count


def _function_record(module, name, node, compiled):
    obj = vars(module)[name]
    lru = None
    if name == "_packet_rules_for":
        wrapper = type(obj) is functools._lru_cache_wrapper
        lru = {"wrapperType": wrapper, "parameters": obj.cache_parameters() if wrapper else None}
        obj = getattr(obj, "__wrapped__", _MISSING)
    defaults = tuple(ast.literal_eval(value) for value in node.args.defaults) or None
    keywords = {arg.arg: ast.literal_eval(value) for arg, value in zip(node.args.kwonlyargs, node.args.kw_defaults)
                if value is not None} or None
    return {"name": name, "lru": lru,
            "codeEqual": getattr(obj, "__code__", _MISSING) == compiled.get(name, _MISSING),
            "globalsIsModule": getattr(obj, "__globals__", _MISSING) is vars(module),
            "defaults": getattr(obj, "__defaults__", _MISSING), "expectedDefaults": defaults,
            "kwdefaults": getattr(obj, "__kwdefaults__", _MISSING), "expectedKwdefaults": keywords,
            "closureIsNone": getattr(obj, "__closure__", _MISSING) is None}


def _import_rows(module, tree):
    statements = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            statements.append(node)
        elif isinstance(node, ast.Try):
            statements += [s for s in node.body + [x for h in node.handlers for x in h.body]
                           if isinstance(s, (ast.Import, ast.ImportFrom))]
        elif isinstance(node, ast.If) and isinstance(node.test, ast.Name) and node.test.id == "__package__":
            statements += node.body + node.orelse
    groups = {}
    for statement in statements:
        if isinstance(statement, ast.ImportFrom) and statement.module == "__future__":
            continue
        for alias in statement.names:
            bound = alias.asname or alias.name.split(".")[0]
            if isinstance(statement, ast.Import):
                target = sys.modules.get(alias.name if alias.asname else alias.name.split(".")[0], _MISSING)
            else:
                source = sys.modules.get(statement.module)
                target = getattr(source, alias.name, _MISSING) if source is not None else _MISSING
            groups.setdefault(bound, []).append(vars(module).get(bound, _MISSING) is target)
    return [{"name": name, "matches": matches} for name, matches in sorted(groups.items())]


def _generic_rows(module, tree):
    found = {}
    for node in tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
        for target in targets:
            if isinstance(target, ast.Name) and target.id in identity.GENERIC_BINDINGS:
                found[target.id] = node.value
    namespace, rows = vars(module), {}
    for name, value in found.items():
        current = namespace.get(name, _MISSING)
        if name in ("MAX_FILE_BYTES", "TEST_PREFIXES"):
            expected = ast.literal_eval(value)
            rows[name] = current == expected and type(current) is type(expected)
        elif name == "ROOT":
            rows[name] = current == Path(module.__file__).resolve().parents[1]
        elif name == "_VERIFIED_AUTHORITY":
            rows[name] = current is None or (type(current) is tuple and len(current) == 2
                                             and current[0] == module.AUTHORITY_SHA256
                                             and hashlib.sha256(current[1]).hexdigest() == module.AUTHORITY_SHA256)
        else:
            builder = namespace.get(value.func.id) if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) \
                else None
            rows[name] = builder is not None and current == builder()
    return rows


def _runtime_records(chain, modules):
    rule, records = _rule(), []
    wanted = set(rule["g1"]) | set(rule["g2"]) | set(identity.D_FUNCTIONS)
    for index, ((slot, name, _, tree), module) in enumerate(zip(chain, modules)):
        path = identity.validator_path(name)
        raw = profile.regular_bytes(path)
        code = compile(raw, str(profile.ROOT / path), "exec", dont_inherit=True)
        compiled = {const.co_name: const for const in code.co_consts if isinstance(const, types.CodeType)}
        tops = identity.top_functions(tree)
        names = wanted | set(rule["p0"].get(str(slot), ()))
        record = {"slot": slot, "module": name,
                  "functions": [_function_record(module, fn, tops[fn], compiled) for fn in sorted(names) if fn in tops],
                  "generic": _generic_rows(module, tree), "imports": _import_rows(module, tree), "successor": None}
        if slot == identity.FIRST_SLOT:
            runner = modules[1]
            pairs = [(alias.asname, alias.name) for node in tree.body if isinstance(node, ast.Try)
                     for statement in node.body if isinstance(statement, ast.ImportFrom) for alias in statement.names
                     if alias.asname in identity.RUNNER_NAMES]
            record["runners"] = {asname: vars(module).get(asname, _MISSING) is vars(runner).get(source, _MISSING)
                                 for asname, source in pairs}
        elif index + 1 < len(chain):
            record["successor"] = vars(module).get("successor", _MISSING) is modules[index + 1]
        record["bytesStable"] = hashlib.sha256(profile.regular_bytes(path)).digest() == hashlib.sha256(raw).digest()
        records.append(record)
    return records


def test_runtime_bindings_are_the_frozen_ones_around_a_fan_in_pass():
    """Item 9 in this worker: every chain validator is imported under its scripts.validate_* name, as tests do; each
    module's successor (or 189's runner_* names), every G1, G2, D and pre-scaffold function's code (compared with the code
    compiled from the module's exact bytes; _packet_rules_for through functools' lru_cache wrapper), globals, defaults
    and closure, the generic bindings and every import-bound global are checked before and after one full fan-in pass."""
    chain = identity.walk_layers(profile.regular_bytes, _rule())
    modules = [importlib.import_module("scripts." + name) for _, name, _, _ in chain]
    assert identity.check_runtime(_runtime_records(chain, modules)) == len(chain)
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
    for module in modules:
        module.historical_bytes(roadmap.MASTER_PATH, master_raw)
    assert identity.check_runtime(_runtime_records(chain, modules)) == len(chain)


def _runtime_record(**changes):
    function = {"name": "digest", "lru": None, "codeEqual": True, "globalsIsModule": True, "defaults": None,
                "expectedDefaults": None, "kwdefaults": None, "expectedKwdefaults": None, "closureIsNone": True}
    cached = dict(function, name="_packet_rules_for", lru={"wrapperType": True, "parameters": {"maxsize": 1, "typed": False}})
    record = {"slot": 230, "module": "validate_runtime_record", "bytesStable": True, "successor": True,
              "functions": [function, cached], "generic": {"MAX_FILE_BYTES": True}, "imports": [{"name": "json",
                                                                                                "matches": [True]}]}
    for key, value in changes.items():
        if key in function:
            record["functions"] = [dict(function, **{key: value}), cached]
        elif key == "lru":
            record["functions"] = [function, dict(cached, lru=value)]
        else:
            record[key] = value
    return record


RUNTIME_FAULTS = [
    ("bytes", {"bytesStable": False}, "runtime bytes"),
    ("successor", {"successor": False}, "runtime successor"),
    ("runner", {"slot": 189, "runners": {"runner_authority": False}}, "runtime runner"),
    ("code", {"codeEqual": False}, "runtime code"),
    ("globals", {"globalsIsModule": False}, "runtime globals"),
    ("defaults", {"defaults": (1,)}, "runtime defaults"),
    ("kwdefaults", {"kwdefaults": {"strict": True}}, "runtime defaults"),
    ("closure", {"closureIsNone": False}, "runtime closure"),
    ("lru_type", {"lru": {"wrapperType": False, "parameters": {"maxsize": 1, "typed": False}}}, "runtime lru_cache"),
    ("lru_size", {"lru": {"wrapperType": True, "parameters": {"maxsize": 2, "typed": False}}}, "runtime lru_cache"),
    ("generic", {"generic": {"MAX_FILE_BYTES": False}}, "runtime generic"),
    ("import", {"imports": [{"name": "json", "matches": [False, False]}]}, "runtime import"),
]


@pytest.mark.parametrize("name, changes, clause", RUNTIME_FAULTS, ids=[row[0] for row in RUNTIME_FAULTS])
def test_each_runtime_predicate_refuses_on_plain_records(name, changes, clause):
    """Item 9's predicates on plain records (dicts; no function object is built): each refuses its own fault."""
    runners = {runner: True for runner in identity.RUNNER_NAMES}
    assert identity.check_runtime([_runtime_record(), _runtime_record(slot=189, runners=runners, successor=None)]) == 2
    if name == "runner":
        changes = {"slot": 189, "runners": dict(runners, runner_authority=False), "successor": None}
    with pytest.raises(ValueError, match="^" + re.escape("identity %s: " % clause)):
        identity.check_runtime([_runtime_record(**changes)])
    with pytest.raises(ValueError, match="^identity runtime: "):
        identity.check_runtime([])


# Identity-only mutants: static source text only ------------------------------------------------------------------------

# Identity-only mutants (PLAN revision 11 section 6, M3 part (ii), classes I1-I9) -----------------------------------------
# Each mutant is source text: one of this era's validator sources with one change. The identity checker parses it and must
# refuse it with the named clause. No mutant is imported, compiled to a function or executed (owner rule, 2026-10-21:
# bypass-form analysis is static only). A bridged layer's mutant meets the step rule against its unchanged previous-era
# source; the head's meets the allow-list.

MUTANT_SLOTS = {"I1": tuple(range(192, 254)), "I2": (200, 216, 230, 250, 254, 255), "I4": (230, 254, 255),
                "I5": (210, 240), "I8": (200, 230, 253), "I9": (210, 230, 250)}
GENERIC_EDITS = (
    ("MAX_FILE_BYTES", "MAX_FILE_BYTES = 16_777_216\n", "MAX_FILE_BYTES = 16_777_217\n"),
    ("ROOT", "ROOT = Path(__file__).resolve().parents[1]\n", "ROOT = Path(__file__).resolve().parents[2]\n"),
    ("TEST_PREFIXES", 'TEST_PREFIXES = ("tests/", "ci/test_")\n', 'TEST_PREFIXES = ("tests/", "ci/test_", "")\n'),
    ("_VERIFIED_AUTHORITY", "_VERIFIED_AUTHORITY: tuple[str, bytes] | None = None\n",
     '_VERIFIED_AUTHORITY: tuple[str, bytes] | None = ("", b"")\n'),
    ("_PROJECTION_RULES", "_PROJECTION_RULES = _rules()\n", "_PROJECTION_RULES = MappingProxyType({})\n"),
    ("_PACKET_BYTE_RULES", "_PACKET_BYTE_RULES = _packet_byte_rules()\n", "_PACKET_BYTE_RULES = MappingProxyType({})\n"),
    ("_NEW_PACKET_RULE", "_NEW_PACKET_RULE = _new_packet_rule()\n", '_NEW_PACKET_RULE = ("", "")\n'),
)
MODULE_STATEMENTS = (("class", "class Unreviewed:\n    pass\n"), ("call", "print(NEW_PACKET)\n"),
                     ("loop", "for _unreviewed in ():\n    pass\n"))
STORES = (("module_store", "    hashlib.sha256 = hashlib.sha256\n", "allow-list foreign store"),
          ("module_dict", '    json.__dict__["loads"] = None\n', "allow-list era loader"),
          ("extra_global", "    global ROOT\n", "allow-list global"),
          ("function_import", "    import sys\n", "allow-list function import"),
          ("sys_modules", '    sys.modules["scripts.unreviewed"] = None\n', "allow-list attribute name"),
          ("function_store", "    _packet_rules.value = None\n", "allow-list foreign store"))
G_FAULTS = (("payload_skip", "validate_packet_payloads",
             "    for name, (_byte_sha, payload_sha) in rules.items():\n",
             "    for name, (_byte_sha, payload_sha) in rules.items():\n        if name == \"MET-001\":\n            continue\n",
             "G1"),
            ("sha_length", "_sha", "len(value) == 64", "len(value) == 63", "G1"),
            ("nlink", "regular_bytes", "before.st_nlink == 1", "before.st_nlink <= 2", "G1"),
            ("inverse_bound", "_inverse", 'require(len(before) <= MAX_FILE_BYTES, "bounded predecessor bytes")',
             'require(len(before) <= MAX_FILE_BYTES + 1, "bounded predecessor bytes")', "G1"),
            ("authority_key", "authority", '"packetSha256", "changedFiles", "newFiles", "validatorNormalizedSha256",',
             '"packetSha256", "changedFiles", "newFiles", "validatorNormalisedSha256",', "G2"),
            ("own_read_pin", "_checked_own_authority_raw", "_VERIFIED_AUTHORITY = (AUTHORITY_SHA256, raw)",
             "_VERIFIED_AUTHORITY = (AUTHORITY_SHA256, raw[:1])", "G2"))
WALK_FAULTS = (
    ("runner_alias", 189, "        authority as runner_authority,\n", "        authority as runner_auth,\n", 2),
    ("package_form", 190, "if __package__:\n", "if __package__ is not None:\n", 1),
    ("mixed_successor", 191, "    from scripts import validate_linux_runner_contract as successor\n",
     "    from scripts import validate_owner_verifier as successor\n", 1),
    ("validate_import", 230, "def validate() -> None:\n", "def validate() -> None:\n    import validate_unified_roadmap\n", 1))
PRE_SCAFFOLD = {189: ("_checked_authority_raw", "_project_changed", "historical_bytes", "historical_test_bytes",
                      "current_test_bytes", "historical_catalog"),
                190: ("_checked_authority_raw", "historical_bytes", "_historical_bytes_this_layer",
                      "historical_test_bytes", "current_test_bytes", "historical_catalog"),
                191: ("_checked_own_authority_raw", "historical_bytes", "_undo_this_layer",
                      "historical_test_bytes", "current_test_bytes", "historical_catalog")}
I8_VARIANTS = (
    ("globals_decorator", "decorator", "@(lambda function: function.__globals__.update({}) or function)\n",
     "allow-list attribute name"),
    ("default_object", "body", "    def _probe(value=json):\n        return value\n", "allow-list alias"),
    ("exec_string", "body", '    exec("successor.NEW_PACKET = None")\n', "allow-list era loader"),
    ("code_swap", "body", "    _sha.__code__ = _path.__code__\n", "allow-list attribute name"),
    ("partial", "body", "    import functools\n", "allow-list function import"),
    ("forwarding", "body", '    proxy = type("Forward", (), {"__getattr__": lambda self, name: getattr(json, name)})\n',
     "allow-list restricted use"),
    ("module_alias", "body", "    alias = hashlib\n", "allow-list alias"),
    ("attribute_chain", "body", "    found = types.sys\n", "allow-list attribute name"),
    ("builtins_call", "body", '    builtins.setattr(json, "loads", None)\n', "allow-list attribute name"))
HEAD_HOSTS = ("validate", "reviewed_bytes", "_verified")
I9_FAULTS = (("count", "len(commands) == 64", "len(commands) == 65"),
             ("depth", None, None),
             ("foreign_id", None, None))
BRIDGE_FAULTS = (
    ("extra_skip", "        if path.stem == successor.NEW_PACKET:\n            continue\n",
     "        if path.stem == successor.NEW_PACKET:\n            continue\n        if path.stem == \"MET-001\":\n"
     "            continue\n"),
    ("extra_lift", "    paths = sorted((ROOT / \"task-packets\").glob(\"*.yaml\"))\n",
     "    paths = sorted((ROOT / \"task-packets\").glob(\"*.yaml\"))\n"
     "    record = parse(successor.historical_bytes(AUTHORITY_PATH, regular_bytes(AUTHORITY_PATH)))\n"),
    ("extra_phrase", "254-packet checkpoint and ", "254-packet checkpoint and 253-packet checkpoint and "))


def identity_mutants():
    """Every identity-only mutant as plain data: (id, placement, slot, change, expected clause)."""
    cases = []
    for slot in MUTANT_SLOTS["I1"]:
        cases.append(("I1-successor-%d" % slot, "step", slot,
                      ("after_successor", "successor = types.SimpleNamespace(**vars(successor))\n"), "step"))
    for name in ("runner_authority", "runner_history", "runner_historical_test", "runner_current_test", "runner_catalog"):
        other = "runner_catalog" if name != "runner_catalog" else "runner_history"
        cases.append(("I1-%s" % name, "step", 189, ("after_runners", "%s = %s\n" % (name, other)), "step"))
    for name, old, new in GENERIC_EDITS:
        for slot in MUTANT_SLOTS["I2"]:
            placement = "head" if slot == 255 else "step"
            cases.append(("I2-%s-%d" % (name, slot), placement, slot, ("replace", old, new),
                          "allow-list generic binding" if placement == "head" else "step"))
    for kind, statement in MODULE_STATEMENTS:
        cases.append(("I3-%s-head" % kind, "head", 255, ("before_def", "validate", statement + "\n\n"),
                      "allow-list module statement"))
        cases.append(("I3-%s-230" % kind, "step", 230, ("before_def", "validate", statement + "\n\n"), "step"))
    for kind, statement, clause in STORES:
        for slot in MUTANT_SLOTS["I4"]:
            placement = "head" if slot == 255 else "step"
            cases.append(("I4-%s-%d" % (kind, slot), placement, slot, ("function_top", "validate", statement),
                          clause if placement == "head" else "step"))
    for kind, function, old, new, clause in G_FAULTS:
        for slot in MUTANT_SLOTS["I5"]:
            cases.append(("I5-%s-%d" % (kind, slot), "classes", slot, ("in_function", function, old, new), clause))
    for kind, slot, old, new, count in WALK_FAULTS:
        cases.append(("I6-%s" % kind, "walk", slot, ("replace_all", old, new, count), "walk"))
    for slot, functions in PRE_SCAFFOLD.items():
        for function in functions:
            cases.append(("I7-%s-%d" % (function, slot), "step", slot, ("append_pass", function), "step"))
    for kind, where, text, clause in I8_VARIANTS:
        for slot in MUTANT_SLOTS["I8"]:
            change = ("before_def", "validate", text) if where == "decorator" else ("function_top", "validate", text)
            cases.append(("I8-%s-%d" % (kind, slot), "step", slot, change, "step"))
        for host in HEAD_HOSTS:
            change = ("before_def", host, text) if where == "decorator" else ("function_top", host, text)
            cases.append(("I8-%s-head-%s" % (kind, host), "head", 255, change, clause))
    for kind, old, new in I9_FAULTS:
        for slot in MUTANT_SLOTS["I9"]:
            change = ("replace", old, new) if old else (kind,)
            cases.append(("I9-%s-%d" % (kind, slot), "step", slot, change, "step"))
    for kind, old, new in BRIDGE_FAULTS:
        cases.append(("I9-bridge-%s" % kind, "step", 254, ("replace", old, new), "step"))
    return cases


def _def_line(lines, function):
    found = [k for k, line in enumerate(lines) if line.startswith("def %s(" % function)]
    assert len(found) == 1 and lines[found[0]].endswith(":"), function
    return found[0]


def apply_change(text, change):
    """The mutated source text (plain string edits; asserting each applies exactly as described)."""
    kind = change[0]
    lines = text.split("\n")
    if kind == "after_successor":
        found = [k for k, line in enumerate(lines) if line.startswith("    from scripts import ")
                 and line.endswith(" as successor")]
        assert len(found) == 1
        lines.insert(found[0] + 1, change[1].rstrip("\n"))
    elif kind == "after_runners":
        found = [k for k, line in enumerate(lines) if line == "        historical_catalog as runner_catalog,"]
        assert len(found) == 2 and lines[found[1] + 1] == "    )"
        lines.insert(found[1] + 2, change[1].rstrip("\n"))
    elif kind == "replace":
        assert text.count(change[1]) == 1, change[1]
        return text.replace(change[1], change[2], 1)
    elif kind == "replace_all":
        assert text.count(change[1]) == change[3], change[1]
        return text.replace(change[1], change[2])
    elif kind == "before_def":
        k = _def_line(lines, change[1])
        lines[k:k] = change[2].rstrip("\n").split("\n")
    elif kind == "function_top":
        k = _def_line(lines, change[1])
        lines[k + 1:k + 1] = change[2].rstrip("\n").split("\n")
    elif kind == "in_function":
        k = _def_line(lines, change[1])
        tree = ast.parse(text)
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == change[1])
        body = "\n".join(lines[k:node.end_lineno])
        assert body.count(change[2]) == 1, change
        lines[k:node.end_lineno] = body.replace(change[2], change[3], 1).split("\n")
    elif kind == "append_pass":
        tree = ast.parse(text)
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == change[1])
        lines.insert(node.end_lineno, "    pass")
    elif kind in ("depth", "foreign_id"):
        tree = ast.parse(text)
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "validate")
        displays = [n for n in ast.walk(fn) if isinstance(n, ast.Set) and n.elts
                    and isinstance(n.elts[-1], ast.Attribute) and n.elts[-1].attr == "NEW_PACKET"]
        assert displays
        display = displays[0]
        line = lines[display.end_lineno - 1]
        end = len(line.encode("utf-8")[:display.end_col_offset].decode("utf-8")) - 1
        assert line[end] == "}"
        if kind == "depth":
            last = display.elts[-1]
            start = len(line.encode("utf-8")[:last.col_offset].decode("utf-8")) if last.lineno == display.end_lineno \
                else None
            assert start is not None
            lines[display.end_lineno - 1] = line[:start] + "successor." + line[start:]
        else:
            lines[display.end_lineno - 1] = line[:end] + ', "MET-PERF-999"' + line[end:]
    else:
        raise AssertionError(kind)
    mutated = "\n".join(lines)
    assert mutated != text
    return mutated


def run_mutant(identity, case, era, previous, rule, shapes, chain_trees, count, newid, head_module):
    """Run one mutant through the checker the placement names: era(slot) and previous(slot) give the slot's source text
    in this era and in the previous one; chain_trees is this era's walked chain, as identity.walk returns it."""
    _, placement, slot, change, _ = case
    mutated = apply_change(era(slot), change)
    tree = identity.parse(mutated, "mutant")
    if placement == "step":
        older = identity.parse(era(slot - 1), "older") if slot == count - 1 else None
        identity.check_step(identity.parse(previous(slot), "previous"), tree, slot, count, newid, count,
                            older=older, new_head=head_module)
    elif placement == "head":
        identity.check_allow_list(count, tree, rule, shapes, True)
    elif placement == "walk":
        identity.successor_form(tree)
    elif placement == "classes":
        chain = [(s, m, t, tree if s == slot else node) for s, m, t, node in chain_trees]
        identity.check_classes(chain, rule, identity.parse(previous(count - 1), "previous head"))
    else:
        raise AssertionError(placement)


@pytest.mark.parametrize("case", identity_mutants(), ids=[case[0] for case in identity_mutants()])
def test_an_identity_only_fault_is_refused(case):
    with pytest.raises(ValueError, match="^" + re.escape("identity %s: " % case[4])):
        run_mutant(identity, case, _era_text, _previous_text, _rule(), _shapes(), _era_chain(), 255,
                   profile.NEW_PACKET, profile.HEAD_MODULE)


# Every remaining clause of the checker, with its own static source-text fault.
CLAUSE_CASES = [
    ("decorator", "head", 255, ("before_def", "_verified", "@lru_cache(maxsize=1)\n"), "allow-list decorator"),
    ("node_type", "head", 255, ("function_top", "_verified", "    match path:\n        case _:\n            pass\n"),
     "allow-list node type"),
    ("module_import", "head", 255, ("before_def", "validate", "import sys\n\n\n"), "allow-list import"),
    ("main_guard", "head", 255, ("replace", '    print("Chain compaction valid:', '    print("Chain compaction" + " valid:'),
     "allow-list main guard"),
    ("module_value", "head", 255, ("before_def", "validate", "UNREVIEWED = vars\n\n\n"), "allow-list module value"),
    ("call_form", "head", 255, ("before_def", "validate", "UNREVIEWED = sorted(())\n\n\n"), "allow-list call form"),
    ("d_class", "classes", 230, ("append_pass", "historical_catalog"), "D"),
    ("p0", "classes", 190, ("replace_all", "def _historical_bytes_this_layer(", "def _historical_bytes_this_step(", 1),
     "P0"),
]


@pytest.mark.parametrize("case", CLAUSE_CASES, ids=[case[0] for case in CLAUSE_CASES])
def test_each_remaining_clause_refuses_its_own_fault(case):
    with pytest.raises(ValueError, match="^" + re.escape("identity %s: " % case[4])):
        run_mutant(identity, case, _era_text, _previous_text, _rule(), _shapes(), _era_chain(), 255,
                   profile.NEW_PACKET, profile.HEAD_MODULE)


def test_the_binding_rule_parse_and_the_rule_record_refuse():
    tree = ast.parse(apply_change(_era_text(230), ("function_top", "validate", "    successor = None\n")))
    with pytest.raises(ValueError, match="^identity binding: "):
        identity.check_binding(230, tree, 255)
    with pytest.raises(ValueError, match="^identity parse: "):
        identity.parse("def (", "fault")
    with pytest.raises(ValueError, match="^identity parse: "):
        identity.text(b"\xff", "fault")
    with pytest.raises(ValueError, match="^identity rule: "):
        identity.check(profile._era_source, profile._undo_this_layer, {"schemaVersion": "unreviewed"}, 255)


# C2's shapes and the fact map over this era, each with its fault --------------------------------------------------------

def _c2_case(change):
    path = "tests/test_parallel_suite.py"
    head, served, facts = profile.HEAD_TEST, {}, json.loads(profile._verified(profile.FACT_MAP))
    text = profile._era_source(path).decode("utf-8")
    head_text = profile._era_source(head).decode("utf-8")
    if change == "non_adjacent_kept":
        served[path] = text.replace('"payloads", "yprofile_old"]', '"payloads", "yprofile_old", "xprofile_old"]', 1)
    elif change == "adjacent_missing":
        served[path] = text.replace('"payloads", "yprofile_old"]', '"payloads"]', 1)
    elif change == "oracle_through_layer":
        served[path] = text.replace("hashlib.sha256(raw).hexdigest(), hashlib", "profile.digest(raw), hashlib", 1)
    elif change == "full_loop_kept":
        served[path] = text.replace('["baselinePackets"])[:1]:', '["baselinePackets"]):', 1)
    elif change == "function_renamed":
        served[path] = text.replace("def test_unlinked_bounded_source_reads(", "def test_unlinked_bounded_reads(", 1)
    elif change == "head_route_missing":
        served[head] = head_text.replace(', "roadmap_old"]', "]", 1)
    elif change == "head_loop_compacted":
        served[head] = head_text.replace('in sorted(profile.authority()["baselinePackets"]):',
                                         'in sorted(profile.authority()["baselinePackets"])[:1]:', 1)
    elif change == "twin_input_differs":
        served[head] = head_text.replace(
            'old_runner = runner.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "runner_old" else None',
            'old_runner = runner.historical_bytes(roadmap.MASTER_PATH, master_raw + b"") if route == "runner_old" else None',
            1)
    elif change == "fact_map_record":
        facts["totals"]["droppedRouteNodes"] += 1
    elif change == "conftest_shares_identity":
        conftest = profile._era_source(profile.CONFTEST).decode("utf-8")
        served[profile.CONFTEST] = conftest.replace('    "%s",\n' % profile.IDENTITY_TESTS[0], "", 1)
    for key, value in served.items():
        assert value != (profile._era_source(key).decode("utf-8")), change
    return _reader({key: value.encode("utf-8") for key, value in served.items()}), facts


C2_FAULTS = [("non_adjacent_kept", "C2 shape"), ("adjacent_missing", "C2 shape"), ("oracle_through_layer", "C2 shape"),
             ("full_loop_kept", "C2 shape"), ("function_renamed", "C2 shape"), ("head_route_missing", "C2 shape"),
             ("head_loop_compacted", "C2 shape"), ("twin_input_differs", "C2 shape"), ("fact_map_record", "fact map"),
             ("conftest_shares_identity", "conftest")]


@pytest.mark.parametrize("change, clause", C2_FAULTS, ids=[row[0] for row in C2_FAULTS])
def test_a_c2_shape_or_fact_map_fault_is_refused(change, clause):
    read, facts = _c2_case(change)
    with pytest.raises(ValueError, match="^" + re.escape("identity %s: " % clause)):
        identity.check_record(read, _era_previous, _rule(), facts, profile.HEAD_MODULE, 255)


def test_the_head_test_keeps_the_full_fan_in_and_loop():
    tree = ast.parse(profile._era_source(profile.HEAD_TEST))
    routes = identity.route_list(tree, profile.HEAD_TEST)
    assert routes[:8] == list(identity.OWN_ROUTES) and len(routes) == 8 + 66
    assert identity.payload_form(tree, identity.PAYLOAD_HEAD, profile.HEAD_TEST) == "profile"


# Reads and the canonical hunks -----------------------------------------------------------------------------------------

SEMANTIC_FUNCTIONS = {"_era_bytes", "_verified", "_head_bytes", "_own_bytes", "_era_source", "_json", "_git_mode",
                      "_era_import", "_era_model", "check_records_tree", "check_record_bytes", "check_cost_report",
                      "check_readme", "check_decisions", "check_identity_rule", "check_ab", "check_seeded_faults",
                      "validate_records", "check_summary", "check_totals", "validate_chain_compaction"}


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
    "MET-PERF-042 reviewed bytes are bound: ": "test_a_path_outside_the_era_is_refused_before_it_is_read",
    "unreviewed CHAIN-COMPACTION source: ": "test_every_era_file_is_bound_by_digest",
    "the head's own bytes are its reviewed bytes": "test_the_heads_own_bytes_are_bound_by_the_authority",
    "the records directory holds exactly its seven records, each of mode 100644": "test_the_records_directory_is_closed",
    "no absolute local path in a record: ": "test_no_record_may_carry_an_absolute_local_path",
    "the cost report is M1's, with its keys": "test_the_cost_report_is_m1s",
    "the README describes both measured records and the one inherited edit outside C2":
        "test_the_readme_describes_both_measured_records",
    "the A/B record's closed shape": "test_the_ab_record_has_its_closed_shape",
    "the A/B record's numbers are consistent": "test_the_ab_record_numbers_are_consistent",
    "the A/B record carries the owner's acceptance verbatim": "test_the_ab_record_carries_the_owners_acceptance",
    "the seeded-faults record's closed shape": "test_the_seeded_faults_record_has_its_closed_shape",
    "the seeded-faults record's numbers are consistent": "test_the_seeded_faults_numbers_are_consistent",
    "the six collection kills are exactly the ruled cases": "test_the_six_collection_kills_are_exactly_the_ruled_cases",
    "the seeded-faults record carries the owner's scope and the monitor's ruling verbatim":
        "test_the_seeded_faults_record_carries_the_owners_scope_and_the_ruling",
    "the decisions are recorded verbatim, each section once": "test_the_decisions_are_recorded_each_section_once",
    "the identity rule is the frozen record": "test_the_identity_rule_is_the_frozen_record",
    "the identity rule ran over this era's whole chain": "test_the_identity_rule_ran_over_the_whole_chain",
    "the fact map's totals": "test_the_fact_map_totals_are_restated",
    "unreviewed current source: ": "test_the_canonical_check_reads_this_eras_bytes",
    "canonical byte-minimal inverse hunks: ": "test_whole_line_hunks_are_refused_where_canonical_ones_differ"}


def _refusal_messages():
    tree = ast.parse(profile.regular_bytes(profile.VALIDATOR_PATH))
    found = set()
    for node in tree.body:
        if not (isinstance(node, ast.FunctionDef)
                and node.name in SEMANTIC_FUNCTIONS | {"check_canonical_hunks", "validate_canonical_hunks"}):
            continue
        for call in ast.walk(node):
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "require":
                message = call.args[1]
                while isinstance(message, ast.BinOp):
                    message = message.left
                assert isinstance(message, ast.Constant) and type(message.value) is str, ast.dump(call)
                found.add(message.value)
    return found


def test_every_check_has_a_test_that_makes_it_fail():
    """Every refusal of this layer's semantic check maps to a test that names it, and every clause of the identity
    checker has at least one failing static case, runtime record or C2 fault."""
    import inspect
    assert _refusal_messages() == set(CHECK_TESTS)
    for message, name in CHECK_TESTS.items():
        assert message in inspect.getsource(globals()[name]), message
    tree = ast.parse(profile.regular_bytes(profile.MODEL))
    clauses = set()
    for call in ast.walk(tree):
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id in ("refuse", "need"):
            clause = call.args[0] if call.func.id == "refuse" else call.args[1]
            if isinstance(clause, ast.Constant):
                clauses.add(clause.value)
    exercised = {case[4] for case in identity_mutants() + CLAUSE_CASES} | {row[2] for row in RUNTIME_FAULTS}
    exercised |= {row[1] for row in C2_FAULTS} | {"binding", "parse", "rule", "runtime"}
    assert clauses <= exercised, sorted(clauses - exercised)


def test_this_file_is_within_its_node_budget():
    """B2: the new test file has at most 700 collected nodes."""
    tree = ast.parse(profile.regular_bytes(profile.HEAD_TEST))
    total = 0
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            count = 1
            for mark in node.decorator_list:
                if isinstance(mark, ast.Call) and getattr(mark.func, "attr", None) == "parametrize":
                    values = mark.args[1]
                    if isinstance(values, (ast.List, ast.Tuple)):
                        count *= len(values.elts)
                    elif isinstance(values, ast.Name):
                        count *= len(globals()[values.id])
                    else:
                        count *= len(identity_mutants())
            total += count
    assert total <= 700, total
