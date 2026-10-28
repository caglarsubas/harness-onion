"""Exact source lineage for MET-ENFORCE-038; capture-only native-profile v5 and edge record v7: native-profile v4's captures without the seven host, policy and boot fields, the record native-profile v4's, the adoption of candidate 4 bound to its four review rounds, native-profile v4's and I06 v3's models frozen, edge record v7 against v6, the class table against the v5 model and the v5 model replaying every vector from its reviewed bytes, checked in the validator."""
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

from scripts import validate_native_profile_v5 as profile
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
    # The newer MET-PERF-041 layer is projected away before this layer's payload checks.
    return profile.successor.historical_catalog(packets())


def changed_test():
    return next(path for path in profile._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert profile.validate() is None
    current = packets()
    accepted = profile.historical_catalog(current)
    assert len(current) == 269 and len(accepted) == 251
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
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET}
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


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "lrp_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = profile.historical_bytes(path, raw) if route in ("current_test", "old_bytes") else None
    current_packets = packets() if route == "catalog" else None
    layer = layer_packets() if route == "payloads" else None
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
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
    with pytest.raises(ValueError, match="native profile v5 history authority digest"):
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
    assert len(profile.historical_catalog(current)) == 251


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
    assert len(profile.historical_catalog(current)) == 251
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
    assert len(rules) == 252 and len(parsed) == 251
    assert profile._packet_rules() is rules and len(parsed) == 251
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
    with pytest.raises(ValueError, match="native profile v5 history authority digest"):
        profile.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = layer_packets()
    profile.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "native-profile-v5-authority.json").write_bytes(
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
    # The newer MET-PERF-041 layer refuses a mutated validator before this layer.
    with pytest.raises(ValueError, match="unreviewed current source: scripts/validate_native_profile_v5.py"):
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
            assert all("validate_" not in alias.name or alias.name == "validate_diagnostic_caps"
                       for alias in node.names)


def _count_authority_reads(monkeypatch):
    counts = {}
    for module in (profile.successor, profile, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner):
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
    expected = {module.__name__: 1 for module in (profile.successor, profile, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner)}
    if route == "current_test":
        # The forward route reads this layer's newest bytes and then projects them forward once more.
        assert all(counts[name] >= 1 for name in expected) and set(counts) == set(expected)
    else:
        assert counts == expected


def _rebind(monkeypatch, served):
    """Serve changed bytes for some paths and re-pin their era digests, so the checks behind the digest binding run."""
    original = profile.reviewed_bytes
    pins = dict(profile.ERA_SHA256)
    for path, raw in served.items():
        if path in pins:
            pins[path] = profile.digest(raw)
    monkeypatch.setattr(profile, "ERA_SHA256", MappingProxyType(pins))
    monkeypatch.setattr(profile, "reviewed_bytes", lambda target: served[target] if target in served else original(target))


def _dump(value):
    return (json.dumps(value, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def _load(path):
    return json.loads(profile.reviewed_bytes(path))


def _status():
    return _load(profile.STATUS_PATH)


def _rebind_record(monkeypatch, number, change):
    """Serve a changed review record with its status row's record digest re-pinned."""
    path = profile.RECORDS[number - 1]
    record = _load(path)
    change(record)
    status = _status()
    status["rounds"][number - 1]["recordSha256"] = profile.digest(_dump(record))
    _rebind(monkeypatch, {path: _dump(record), profile.STATUS_PATH: _dump(status)})


VALIDATE = profile.validate_native_profile_v5
LAST_RECORD = profile.RECORDS[-1]


def test_the_contract_holds_for_this_era():
    assert VALIDATE() is None


def test_every_added_file_round_record_and_read_input_is_pinned():
    pinned = set(profile.ERA_SHA256)
    status = _status()
    assert len(profile.NEW_FILES) == 12 and len(profile.FROZEN_PATHS) == 38 and len(pinned) == 50
    assert set(profile.NEW_FILES) | set(profile.FROZEN_PATHS) == pinned and not set(profile.NEW_FILES) & set(profile.FROZEN_PATHS)
    assert {row["record"] for row in status["rounds"]} == set(profile.RECORDS) and tuple(status["adoptedSubject"]) == profile.SUBJECT
    assert set(profile.NP5_INPUTS.values()) | set(profile.INDEX_INPUTS) | set(profile.MODEL_FREEZE) <= set(profile.FROZEN_PATHS)
    assert {row[0] for row in profile.NEW_ROWS} <= pinned and profile.V6_EDGE in profile.FROZEN_PATHS
    assert not any(path.startswith(profile.FROZEN_PREFIXES) for path in profile.NEW_FILES)
    assert [path for path in profile.FROZEN_PATHS if path.startswith(profile.EDGES_DIR)] == sorted(
        profile.EDGES_DIR + name for name in ["README.md"] + ["README-v%d.md" % n for n in range(2, 7)]
        + ["operator-harness-engineering.json"] + ["operator-harness-engineering-v%d.json" % n for n in range(2, 7)])
    for path, expected in profile.ERA_SHA256.items():
        assert profile.digest(profile.reviewed_bytes(path)) == expected


@pytest.mark.parametrize("path", sorted(profile.ERA_SHA256))
def test_every_era_file_is_bound_by_digest_before_anything_runs(monkeypatch, path):
    original = profile.reviewed_bytes
    executed = []
    monkeypatch.setattr(profile, "reviewed_bytes", lambda target: original(target) + b" " if target == path else original(target))
    monkeypatch.setattr(profile, "validate_freeze", lambda: executed.append(True))
    monkeypatch.setattr(profile, "era_modules", lambda: executed.append(True))
    with pytest.raises(ValueError, match=re.escape("unreviewed NATIVE-PROFILE-V5 source: " + path)):
        VALIDATE()
    assert executed == []


@pytest.mark.parametrize("path", ["architecture/native-profile-v5/notes.md", "README.md", None])
def test_a_path_outside_the_era_is_refused_before_it_is_read(monkeypatch, path):
    read = []
    monkeypatch.setattr(profile, "reviewed_bytes", lambda target: read.append(target) or b"")
    with pytest.raises(ValueError, match=re.escape("MET-ENFORCE-038 reviewed bytes are bound: " + str(path))):
        profile._verified(path)
    assert read == []


# The freeze (E1-7) ----------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("path", sorted(profile.MODEL_FREEZE))
def test_the_v4_and_i06_v3_models_are_frozen_by_exact_path_and_digest(monkeypatch, path):
    _rebind(monkeypatch, {path: profile.reviewed_bytes(path) + b"\n# a later edit\n"})
    with pytest.raises(ValueError, match=re.escape("frozen by exact path and digest: " + path)):
        VALIDATE()


@pytest.mark.parametrize("path", sorted(profile.MODEL_FREEZE))
def test_the_frozen_digests_are_restated_not_derived(monkeypatch, path):
    monkeypatch.setattr(profile, "MODEL_FREEZE", MappingProxyType(dict(profile.MODEL_FREEZE, **{path: "0" * 64})))
    with pytest.raises(ValueError, match=re.escape("frozen by exact path and digest: " + path)):
        profile.validate_freeze()


def test_the_frozen_models_are_the_ones_the_contract_names():
    assert dict(profile.MODEL_FREEZE) == {
        "scripts/native_qualification_v4.py": "f7c718072d1ffbb9b8bbc310e6141d476ea5f25296f70ff8c1bc9ada3db02387",
        "scripts/i06_backend_profile_v3.py": "dfb00e90199d436ae63b79261f2e04870d7861cb0f7a424971657a4d777754de"}
    pins = {row["path"]: row["sha256"] for row in _load(profile.NP5_INDEX)["predecessorInputs"]}
    assert all(pins[path] == digest for path, digest in profile.MODEL_FREEZE.items())
    assert {"scripts/native_qualification_v2.py", "scripts/native_qualification_v3.py", "scripts/i06_backend_profile.py",
            "scripts/i06_backend_profile_v2.py"} <= set(profile.FROZEN_PATHS)


@pytest.mark.parametrize("path", profile.FROZEN_PATHS)
def test_the_predecessors_models_pins_and_edge_records_may_not_change(monkeypatch, path):
    rules = dict(profile._PROJECTION_RULES)
    rules[path] = rules[next(iter(rules))]
    monkeypatch.setattr(profile, "_PROJECTION_RULES", MappingProxyType(rules))
    with pytest.raises(ValueError, match=re.escape(profile.FROZEN_MESSAGE)):
        VALIDATE()


@pytest.mark.parametrize("prefix", profile.FROZEN_PREFIXES)
def test_no_file_under_a_predecessor_directory_may_change(monkeypatch, prefix):
    rules = dict(profile._PROJECTION_RULES)
    rules[prefix + "unlisted.json"] = rules[next(iter(rules))]
    monkeypatch.setattr(profile, "_PROJECTION_RULES", MappingProxyType(rules))
    with pytest.raises(ValueError, match=re.escape(profile.FROZEN_MESSAGE)):
        VALIDATE()


@pytest.mark.parametrize("path", [prefix + "added.json" for prefix in profile.FROZEN_PREFIXES]
                         + [profile.EDGES_DIR + "operator-harness-engineering-v8.json", profile.EDGES_DIR + "README-v8.md"])
def test_no_file_this_packet_adds_may_sit_under_a_predecessor_directory_or_be_another_edge_record(monkeypatch, path):
    record = copy.deepcopy(profile.authority())
    record["newFiles"][path] = "0" * 64
    monkeypatch.setattr(profile, "authority", lambda: record)
    with pytest.raises(ValueError, match=re.escape(profile.FROZEN_MESSAGE)):
        VALIDATE()


@pytest.mark.parametrize("change", ["missing", "extra", "changed"])
def test_the_contract_files_are_new_in_this_packet_each_once(monkeypatch, change):
    record = copy.deepcopy(profile.authority())
    if change == "missing":
        del record["newFiles"][profile.NP5_INDEX]
    elif change == "extra":
        record["newFiles"][profile.NP5_DIR + "review-round5.json"] = "0" * 64
    else:
        rules = dict(profile._PROJECTION_RULES)
        rules[profile.NP5_SCHEMA] = rules[next(iter(rules))]
        monkeypatch.setattr(profile, "_PROJECTION_RULES", MappingProxyType(rules))
    monkeypatch.setattr(profile, "authority", lambda: record)
    with pytest.raises(ValueError, match="the contract's files are new in this packet, each once"):
        VALIDATE()


@pytest.mark.parametrize("change, message", [
    ("later_file", "the contract directory holds exactly its files"),
    ("missing_file", "the contract directory holds exactly its files"),
    ("executable", "a contract file is a regular file of git mode 100644: " + profile.STATUS_PATH),
    ("symlink", "a contract file is a regular file of git mode 100644: " + profile.NP5_README),
    ("edge_executable", "a contract file is a regular file of git mode 100644: " + profile.V7_EDGE)])
def test_the_contract_tree_is_closed_and_every_file_is_mode_100644(monkeypatch, change, message):
    tree = dict(profile.reviewed_tree(profile.NP5_DIR))
    modes = {}
    if change == "later_file":
        tree[profile.NP5_DIR + "later.json"] = stat.S_IFREG | 0o644
    elif change == "missing_file":
        del tree[profile.RECORDS[0]]
    elif change == "executable":
        modes[profile.STATUS_PATH] = stat.S_IFREG | 0o755
    elif change == "symlink":
        modes[profile.NP5_README] = stat.S_IFLNK | 0o777
    else:
        modes[profile.V7_EDGE] = stat.S_IFREG | 0o755
    original = profile.reviewed_mode
    monkeypatch.setattr(profile, "reviewed_tree", lambda directory: tree)
    monkeypatch.setattr(profile, "reviewed_mode", lambda path: modes.get(path) or original(path))
    with pytest.raises(ValueError, match=re.escape(message)):
        VALIDATE()


def test_the_contract_tree_is_read_from_the_checkout():
    tree = profile.reviewed_tree(profile.NP5_DIR)
    assert set(tree) == profile.CONTRACT_TREE and len(profile.CONTRACT_TREE) == 9
    assert all(stat.S_ISREG(tree[path]) and not tree[path] & 0o111 for path in profile.CONTRACT_TREE)


def test_the_contract_directory_must_not_be_a_link(monkeypatch):
    original = profile.reviewed_mode
    monkeypatch.setattr(profile, "reviewed_mode", lambda path: stat.S_IFLNK | 0o777 if path == profile.NP5_DIR[:-1]
                        else original(path))
    with pytest.raises(ValueError, match="the contract directory is a directory, not a link"):
        VALIDATE()


@pytest.mark.parametrize("path", [profile.NP5_README, LAST_RECORD, profile.V7_README])
def test_no_added_file_may_carry_an_absolute_local_path(monkeypatch, path):
    local = "/".join(["", "Users", "someone", "x"])   # spelled in parts, so this file holds no such path
    if path.endswith(".md"):
        raw = profile.reviewed_bytes(path) + b"\nsee " + local.encode("utf-8") + b"\n"
    else:
        record = _load(path)
        record["checks"].append({"check": "scratch", "result": local})
        raw = _dump(record)
    _rebind(monkeypatch, {path: raw})
    with pytest.raises(ValueError, match=re.escape("no absolute local path in a file this packet adds: " + path)):
        VALIDATE()


# The adoption ---------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("change", ["schema", "work_item", "packet", "slot", "state", "candidate", "adoption", "base",
                                    "review_base", "reviewer", "note", "note_lines", "record_paths", "non_claims", "closed",
                                    "closed_order", "carried_dropped", "carried_order", "carried_elsewhere",
                                    "carried_action", "host_proofs", "extra_key", "key_order"])
def test_the_status_is_closed_and_records_the_adoption(monkeypatch, change):
    status = _status()
    carried = status["carried"]
    if change == "schema":
        status["schemaVersion"] = "planeon.internal.native-profile-v5-status/v2"
    elif change == "work_item":
        status["workItem"] = "NATIVE-PROFILE-V4"
    elif change == "packet":
        status["packet"] = "MET-ENFORCE-039"
    elif change == "slot":
        status["slot"] = 253
    elif change == "state":
        status["status"] = "CONTRACT_CANDIDATE"
    elif change == "candidate":
        status["candidate"] = 3
    elif change == "adoption":
        status["adoption"]["decision"] += " (paraphrased)"
    elif change == "base":
        status["baseMain"] = profile.REVIEW_BASE
    elif change == "review_base":
        status["reviewBase"] = status["baseMain"]
    elif change == "reviewer":
        status["independentReviewer"] = "AUTHOR"
    elif change == "note":
        status["readmeStatusNote"] = ""
    elif change == "note_lines":
        status["readmeStatusNote"] = status["readmeStatusNote"].replace("no README line moved", "README lines kept")
    elif change == "record_paths":
        status["recordPaths"] = " "
    elif change == "non_claims":
        status["nonClaims"].pop()
    elif change == "closed":
        status["closedFindings"]["E1-4"] = "CLOSED in round 2"
    elif change == "closed_order":
        status["closedFindings"] = dict(reversed(list(status["closedFindings"].items())))
    elif change == "carried_dropped":
        status["carried"] = carried[1:]
    elif change == "carried_order":
        carried[0], carried[1] = carried[1], carried[0]
    elif change == "carried_elsewhere":
        carried[2]["to"] = "nobody"
    elif change == "carried_action":
        carried[4]["action"] = " "
    elif change == "host_proofs":
        status["hostProofs"][0]["proof"] = "T04-HOST"
    elif change == "extra_key":
        status["installed"] = False
    else:
        status = {key: status[key] for key in reversed(list(status))}
    _rebind(monkeypatch, {profile.STATUS_PATH: _dump(status)})
    with pytest.raises(ValueError, match="adopted NATIVE-PROFILE-V5 status"):
        VALIDATE()


def test_the_adoption_is_the_monitors_decision_verbatim():
    decision = profile.ADOPTION["decision"]
    assert profile.ADOPTION["decidedBy"] == "the lane monitor, owner-delegated" and profile.ADOPTION["date"] == "2026-10-19"
    assert decision.startswith("Monitor: ADOPT candidate 4 for slot 252 (NATIVE-PROFILE-V5), on r4 PASS_FOR_ADOPTION "
                               "(b8356184).")
    assert decision.endswith("Carry E4-1 and E4-2; record the mechanics base 35b733b in status.json at adoption.")
    assert all(digest[:8] in decision for digest in profile.CANDIDATE_SHA256.values())
    assert _status()["adoption"] == profile.ADOPTION


@pytest.mark.parametrize("change", ["owner_decision", "count", "scope_erratum", "discharge", "carried_item", "carried_to",
                                    "non_claim", "earlier_round", "supersedes", "contracts", "keeps"])
def test_the_status_record_is_candidate_4_with_only_the_adoption_fields(monkeypatch, change):
    status = _status()
    if change == "owner_decision":
        status["ownerDecisions"][1] += " "
    elif change == "count":
        status["counts"]["checks"] = 285
    elif change == "scope_erratum":
        status["scopeErratum"] = status["scopeErratum"].replace("eighth", "ninth")
    elif change == "discharge":
        status["discharges"][0]["line"] = 150
    elif change == "carried_item":
        monkeypatch.setattr(profile, "CARRIED", tuple((item + " " if n == 4 else item, to)
                                                      for n, (item, to) in enumerate(profile.CARRIED)))
        status["carried"][4]["item"] += " "
    elif change == "carried_to":
        monkeypatch.setattr(profile, "CARRIED", tuple((item, "T05" if n == 3 else to)
                                                      for n, (item, to) in enumerate(profile.CARRIED)))
        status["carried"][3]["to"] = "T05"
    elif change == "non_claim":
        monkeypatch.setattr(profile, "NON_CLAIMS", [text + "." if n == 0 else text
                                                    for n, text in enumerate(profile.NON_CLAIMS)])
        status["nonClaims"][0] += "."
    elif change == "earlier_round":
        status["rounds"][0]["verdict"] = "PASS_FOR_ADOPTION"
    elif change == "supersedes":
        status["supersedes"].pop()
    elif change == "contracts":
        status["contracts"]["edgeRecordV7"]["readme"] = profile.EDGES_DIR + "README-v6.md"
    else:
        status["keeps"]["contract"] = "architecture/native-profile-v3/"
    _rebind(monkeypatch, {profile.STATUS_PATH: _dump(status)})
    with pytest.raises(ValueError, match="the status record is candidate 4's with only the adoption fields added"):
        VALIDATE()


def test_removing_the_adoption_fields_gives_candidate_4_back():
    status = _status()
    assert profile.digest(profile.candidate_status(status)) == profile.CANDIDATE_SHA256[profile.STATUS_PATH]
    assert set(status) - set(json.loads(profile.candidate_status(status))) == profile.ADOPTION_KEYS
    assert len(status["carried"]) == profile.ADOPTION_CARRIED + 5 and len(status["nonClaims"]) == profile.CANDIDATE_NON_CLAIMS + 2
    assert [row["item"].split(" ")[0] for row in status["carried"][:profile.ADOPTION_CARRIED]] == ["E4-1", "E4-2", "E1-7"]


@pytest.mark.parametrize("path", [path for path in profile.SUBJECT if path != profile.V7_EDGE])
def test_every_adopted_file_is_candidate_4(monkeypatch, path):
    _rebind(monkeypatch, {path: profile.reviewed_bytes(path) + b"\n"})
    with pytest.raises(ValueError, match=re.escape("the adopted files are candidate 4: " + path)):
        VALIDATE()


@pytest.mark.parametrize("change", ["one_left", "other_packet", "fourth", "line_added", "reformatted"])
def test_edge_record_v7_is_candidate_4_with_only_the_three_values_set(monkeypatch, change):
    raw = profile.reviewed_bytes(profile.V7_EDGE)
    if change == "one_left":
        raw = raw.replace(profile.ASSIGNED, profile.TBD, 1)
    elif change == "other_packet":
        raw = raw.replace(profile.ASSIGNED, b'"providerPacket": "MET-ENFORCE-039"', 1)
    elif change == "fourth":
        raw = raw.replace(b'"providerPacket": "MET-ENFORCE-036"', profile.ASSIGNED, 1)
    elif change == "line_added":
        raw = raw.replace(b"\n  {\n", b"\n\n  {\n", 1)
    else:
        raw = (json.dumps(json.loads(raw), indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    _rebind(monkeypatch, {profile.V7_EDGE: raw})
    with pytest.raises(ValueError, match="edge record v7 is candidate 4 with exactly three providerPacket values set"):
        VALIDATE()


@pytest.mark.parametrize("change", ["adopted", "adopted_order", "count", "rows", "candidate", "line_count", "key_order",
                                    "extra_key"])
def test_the_status_records_the_adopted_files_and_the_one_edit(monkeypatch, change):
    status = _status()
    edit = status["adoptionEdit"]
    if change == "adopted":
        status["adoptedSubject"][profile.NP5_SCHEMA] = "0" * 64
    elif change == "adopted_order":
        status["adoptedSubject"] = dict(reversed(list(status["adoptedSubject"].items())))
    elif change == "count":
        edit["count"] = 2
    elif change == "rows":
        edit["rows"] = edit["rows"][::-1]
    elif change == "candidate":
        edit["candidateSha256"] = edit["adoptedSha256"]
    elif change == "line_count":
        edit["lineCount"] += 1
    elif change == "key_order":
        status["adoptionEdit"] = dict(reversed(list(edit.items())))
    else:
        edit["linesMoved"] = 0
    _rebind(monkeypatch, {profile.STATUS_PATH: _dump(status)})
    with pytest.raises(ValueError, match="the status records the adopted files and the one adoption edit"):
        VALIDATE()


@pytest.mark.parametrize("change, message", [
    ("count", "four review rounds in order"), ("last_verdict", "four review rounds in order"),
    ("last_builder", "four review rounds in order"), ("record_path", "four review rounds in order"),
    ("candidate", "four review rounds in order"), ("extra_key", "four review rounds in order"),
    ("record_sha", "review round 4 is bound"), ("subject_value", "review round 2 is bound"),
    ("subject_keys", "review round 1 is bound"), ("subject_order", "review round 3 is bound"),
    ("severities", "review round 2 is bound"),
    ("earlier_digest", "the status record is candidate 4's with only the adoption fields added")])
def test_each_round_is_bound_to_its_record_and_its_subject_candidate(monkeypatch, change, message):
    status = _status()
    rounds = status["rounds"]
    if change == "count":
        rounds.pop()
    elif change == "last_verdict":
        rounds[3]["verdict"] = "CHANGES_REQUIRED"
    elif change == "last_builder":
        rounds[3]["subjectBuilderSha256"] = rounds[2]["subjectBuilderSha256"]
    elif change == "record_path":
        rounds[1]["record"] = profile.RECORDS[2]
    elif change == "candidate":
        rounds[2]["candidate"] = 2
    elif change == "extra_key":
        rounds[3]["snapshot"] = None
    elif change == "record_sha":
        rounds[3]["recordSha256"] = "0" * 64
    elif change == "subject_value":
        rounds[1]["subjectSha256"][profile.NP5_MODEL] = "0" * 64
    elif change == "subject_keys":
        rounds[0]["subjectSha256"].pop(profile.V7_EDGE)
    elif change == "subject_order":
        rounds[2]["subjectSha256"] = dict(reversed(list(rounds[2]["subjectSha256"].items())))
    elif change == "severities":
        rounds[1]["severities"] = ["MAJOR"]
    else:
        rounds[0]["recordSha256"] = "0" * 64
    _rebind(monkeypatch, {profile.STATUS_PATH: _dump(status)})
    with pytest.raises(ValueError, match=re.escape(message)):
        VALIDATE()


@pytest.mark.parametrize("number", [1, 2, 3, 4])
def test_each_rounds_subject_digests_are_restated(monkeypatch, number):
    subjects = dict(profile.ROUND_SUBJECTS)
    subjects[number] = MappingProxyType(dict(subjects[number], **{profile.NP5_VECTORS: "0" * 64}))
    monkeypatch.setattr(profile, "ROUND_SUBJECTS", MappingProxyType(subjects))
    with pytest.raises(ValueError, match="review round %d is bound to its record and its subject candidate" % number):
        VALIDATE()


def test_the_round_subjects_are_the_candidates_the_records_name():
    for number, verdict, builder, ids in profile.ROUNDS:
        record = _load(profile.RECORDS[number - 1])
        path, label = profile.SUBJECT_NAMES[number]
        assert record["subject"] == profile.SUBJECT_LINE % (number, builder, label, profile.ROUND_SUBJECTS[number][path])
        assert record["verdict"] == verdict and tuple(row["id"] for row in record["findings"]) == ids
    assert dict(profile.ROUND_SUBJECTS[4]) == dict(profile.CANDIDATE_SHA256)
    assert all(dict(profile.ROUND_SUBJECTS[n]) != dict(profile.CANDIDATE_SHA256) for n in (1, 2, 3))


@pytest.mark.parametrize("key, value", [("reviewer", "the author"), ("verdict", "CHANGES_REQUIRED"),
                                        ("actions", dict(profile.ACTIONS, networkAccessed="crates.io")),
                                        ("subject", "tools/w03/npv4-errata candidate 3"), ("findings", []), ("round", 3)])
def test_the_last_record_matches_its_status_row(monkeypatch, key, value):
    _rebind_record(monkeypatch, 4, lambda record: record.__setitem__(key, value))
    with pytest.raises(ValueError, match="review round 4 is bound to its record and its subject candidate"):
        VALIDATE()


@pytest.mark.parametrize("number", [1, 2, 3])
def test_an_earlier_record_is_bound_by_candidate_4s_record_and_the_source_index(monkeypatch, number):
    _rebind_record(monkeypatch, number, lambda record: record.__setitem__("reviewer", "the author"))
    with pytest.raises(ValueError, match="the status record is candidate 4's with only the adoption fields added"):
        VALIDATE()


def test_the_passing_rounds_left_notes_only(monkeypatch):
    def change(record):
        record["findings"][0]["severity"] = "MINOR"
    path = LAST_RECORD
    record = _load(path)
    change(record)
    status = _status()
    status["rounds"][3]["recordSha256"] = profile.digest(_dump(record))
    status["rounds"][3]["severities"] = ["MINOR", "NOTE"]
    _rebind(monkeypatch, {path: _dump(record), profile.STATUS_PATH: _dump(status)})
    with pytest.raises(ValueError, match="the passing rounds left NOTEs only, and the last reviewed candidate 4"):
        VALIDATE()


@pytest.mark.parametrize("change", ["q03_check", "q03_failed", "e31_check", "closed_constant"])
def test_the_closed_findings_are_the_later_rounds_resolutions(monkeypatch, change):
    if change == "closed_constant":
        closed = dict(profile.CLOSED_FINDINGS, **{"E2-1": "CLOSED in round 2"})
        monkeypatch.setattr(profile, "CLOSED_FINDINGS", closed)
        status = _status()
        status["closedFindings"] = closed
        _rebind(monkeypatch, {profile.STATUS_PATH: _dump(status)})
    else:
        def edit(record):
            for check in record["checks"]:
                if change == "q03_check" and check["check"].startswith("Q03 (Q-NPE-9 (a))"):
                    check["check"] = "Q03"
                elif change == "q03_failed" and check["check"].startswith("Q03 (Q-NPE-9 (a))"):
                    check["result"] = "FAIL: " + check["result"]
                elif change == "e31_check" and check["check"] == "E3-1":
                    check["result"] = "FAIL"
        _rebind_record(monkeypatch, 4, edit)
    with pytest.raises(ValueError, match="the closed findings are the later rounds' resolutions"):
        VALIDATE()


# The source index -----------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("change, message", [
    ("base", "the source index is round 4 over the review base"), ("tree", "the source index is round 4 over the review base"),
    ("round", "the source index is round 4 over the review base"),
    ("subject_list", "the source index is round 4 over the review base"),
    ("inputs_list", "the source index is round 4 over the review base"),
    ("earlier", "the source index is round 4 over the review base"),
    ("subject_pin", "every source-index pin holds: " + profile.NP5_README),
    ("input_pin", "every source-index pin holds: architecture/native-profile-v4/README.md"),
    ("input_bytes", "every source-index pin holds: architecture/w03-plan-v2/plan.json"),
    ("unbound_pin", "the source index is round 4 over the review base")])
def test_the_source_index_and_every_pin_hold(monkeypatch, change, message):
    index = _load(profile.NP5_INDEX)
    served = {}
    if change == "base":
        index["baseMain"] = profile.BASE_COMMIT
    elif change == "tree":
        index["baseTree"] = "0" * 40
    elif change == "round":
        index["round"] = 3
    elif change == "subject_list":
        index["subject"].pop()
    elif change == "inputs_list":
        index["predecessorInputs"] = index["predecessorInputs"][::-1]
    elif change == "earlier":
        index["earlierRounds"][2]["recordSha256"] = "0" * 64
    elif change == "subject_pin":
        index["subject"][0]["sha256"] = "0" * 64
    elif change == "input_pin":
        index["predecessorInputs"][0]["sha256"] = "0" * 64
    elif change == "unbound_pin":
        index["predecessorInputs"].append({"path": "architecture/native-profile-v3/round1/README.md", "sha256": "0" * 64})
    else:
        path = "architecture/w03-plan-v2/plan.json"
        served[path] = profile.reviewed_bytes(path) + b"\n"
    if change != "input_bytes":
        served[profile.NP5_INDEX] = _dump(index)
    _rebind(monkeypatch, served)
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.validate_source_index(_status())


# Edge record v7 -------------------------------------------------------------------------------------------------------

def _mutate_edge(value, change):
    rows = value["artifacts"]
    if change == "v6_row_changed":
        rows[0]["mode"] = "100755" if rows[0]["mode"] == "100644" else "100644"
    elif change == "v6_rows_reordered":
        rows[0], rows[1] = rows[1], rows[0]
    elif change == "v6_row_dropped":
        del rows[5]
    elif change == "v6_row_key_order":
        rows[2] = dict(reversed(list(rows[2].items())))
    elif change == "extra_row":
        rows.append(dict(rows[-1], providerPath="architecture/native-profile-v5/status.json"))
    elif change == "published_sha":
        rows[56]["sha256"] = "0" * 64
    elif change == "published_commit":
        rows[57]["providerCommit"] = "0" * 40
    elif change == "published_packet":
        rows[58]["providerPacket"] = "MET-ENFORCE-036"
    elif change == "published_tbd":
        rows[56]["providerPacket"] = "TBD"
    elif change == "published_packet_missing":
        del rows[57]["providerPacket"]
    elif change == "history_commit":
        rows[59]["providerCommit"] = rows[60]["providerCommit"]
    elif change == "history_packet":
        rows[60]["providerPacket"] = rows[56]["providerPacket"]
    elif change == "history_mode":
        rows[61]["mode"] = "100755"
    elif change == "history_sha":
        rows[59]["sha256"] = rows[60]["sha256"]
    elif change == "new_consumer":
        rows[61]["consumerPath"] = rows[61]["consumerPath"].replace("host-enforcement/contracts/", "contracts/")
    elif change == "new_status":
        rows[56]["status"] = "IN_USE"
    elif change == "new_relation":
        rows[57]["relation"] = "DERIVED"
    elif change == "new_consumer_packet":
        rows[58]["consumerPacket"] = "HE-004D1"
    elif change == "consumer_twice":
        rows[60]["consumerPath"] = rows[59]["consumerPath"]
    elif change == "supersedes_digest":
        value["supersedes"]["sha256"] = "sha256:" + "0" * 64
    elif change == "supersedes_packet":
        value["supersedes"]["packet"] = "MET-ENFORCE-033"
    elif change == "schema":
        value["schemaVersion"] = "planeon.internal.artifact-edge-registry/v3"
    elif change == "rules":
        value["rules"].append("A consumer may hold another version.")
    elif change == "artifact":
        value["artifact"] = "native-profile-v5"
    elif change == "notes":
        value["notes"] = []
    elif change == "key_order":
        value["graph"] = value.pop("graph")
    else:
        raise AssertionError(change)


@pytest.mark.parametrize("change, message", [
    ("v6_row_changed", "edge record v7 carries v6's 56 rows exactly and in order"),
    ("v6_rows_reordered", "edge record v7 carries v6's 56 rows exactly and in order"),
    ("v6_row_dropped", "edge record v7 carries v6's 56 rows exactly and in order"),
    ("v6_row_key_order", "edge record v7 carries v6's 56 rows exactly and in order"),
    ("extra_row", "edge record v7 carries v6's 56 rows exactly and in order"),
    ("published_sha", "edge record v7 row 57 registers"), ("published_commit", "edge record v7 row 58 registers"),
    ("published_packet", "edge record v7 row 59 registers"), ("published_tbd", "edge record v7 row 57 registers"),
    ("published_packet_missing", "edge record v7 row 58 registers"), ("history_commit", "edge record v7 row 60 registers"),
    ("history_packet", "edge record v7 row 61 registers"), ("history_mode", "edge record v7 row 62 registers"),
    ("history_sha", "edge record v7 row 60 registers"), ("new_consumer", "edge record v7 row 62 registers"),
    ("new_status", "edge record v7 row 57 registers"), ("new_relation", "edge record v7 row 58 registers"),
    ("new_consumer_packet", "edge record v7 row 59 registers"),
    ("consumer_twice", "edge record v7 row 61 registers"),
    ("supersedes_digest", "edge record v7 supersedes v6 by its digest and packet"),
    ("supersedes_packet", "edge record v7 supersedes v6 by its digest and packet"),
    ("schema", "edge record v7 supersedes v6 by its digest and packet"),
    ("rules", "edge record v7 supersedes v6 by its digest and packet"),
    ("artifact", "edge record v7 supersedes v6 by its digest and packet"),
    ("notes", "edge record v7 supersedes v6 by its digest and packet"),
    ("key_order", "edge record v7 supersedes v6 by its digest and packet")])
def test_every_edge_record_rule_is_checked(monkeypatch, change, message):
    value = _load(profile.V7_EDGE)
    _mutate_edge(value, change)
    _rebind(monkeypatch, {profile.V7_EDGE: _dump(value)})
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.validate_edge_record_v7()


def test_each_consumer_is_registered_once(monkeypatch):
    original = profile.NEW_ROWS
    rows = list(original)
    rows[4] = (rows[4][0], rows[4][1], rows[3][2], rows[4][3])
    value = _load(profile.V7_EDGE)
    value["artifacts"][60]["consumerPath"] = rows[3][2]
    monkeypatch.setattr(profile, "NEW_ROWS", tuple(rows))
    _rebind(monkeypatch, {profile.V7_EDGE: _dump(value)})
    with pytest.raises(ValueError, match="each provider path, and each new consumer path, is registered once"):
        profile.validate_edge_record_v7()


def test_edge_record_v6_is_the_one_v7_supersedes(monkeypatch):
    _rebind(monkeypatch, {profile.V6_EDGE: profile.reviewed_bytes(profile.V6_EDGE) + b"\n"})
    with pytest.raises(ValueError, match="edge record v7 supersedes v6 by its digest and packet"):
        profile.validate_edge_record_v7()


@pytest.mark.parametrize("number", [57, 59, 60, 62])
def test_a_changed_provider_file_is_refused(monkeypatch, number):
    path = profile.NEW_ROWS[number - 57][0]
    _rebind(monkeypatch, {path: profile.reviewed_bytes(path) + b"\n"})
    with pytest.raises(ValueError, match=re.escape("edge record v7 row %d registers its provider's exact bytes and mode "
                                                   "before use: %s" % (number, path))):
        profile.validate_edge_record_v7()


@pytest.mark.parametrize("mode", [stat.S_IFREG | 0o755, stat.S_IFLNK | 0o777])
def test_a_provider_files_mode_is_its_registered_mode(monkeypatch, mode):
    path = profile.NEW_ROWS[-1][0]
    original = profile.reviewed_mode
    monkeypatch.setattr(profile, "reviewed_mode", lambda target: mode if target == path else original(target))
    with pytest.raises(ValueError, match=re.escape("edge record v7 row 62 registers")):
        profile.validate_edge_record_v7()


def test_the_new_rows_are_restated_with_their_commits_and_this_packet():
    rows = _load(profile.V7_EDGE)["artifacts"][profile.V6_ROWS:]
    assert [(row["providerPath"], row["providerCommit"], row["consumerPath"], row["consumerPacket"]) for row in rows] == [
        tuple(row) for row in profile.NEW_ROWS]
    assert [row[1] is None for row in profile.NEW_ROWS] == [True] * 3 + [False] * 3
    assert [row[1][:8] for row in profile.NEW_ROWS[3:]] == ["3f52d53c", "46bcc3e3", "a29c93c7"]
    assert [row[0] for row in profile.NEW_ROWS[:3]] == [profile.NP5_SCHEMA, profile.NP5_VECTORS, profile.NP5_README]
    assert [row[3] for row in profile.NEW_ROWS] == ["HE-004D2"] * 6
    assert [row["providerPacket"] for row in rows if row["providerCommit"] is None] == [profile.NEW_PACKET] * 3
    assert all("providerPacket" not in row for row in rows[3:])
    assert profile.ASSIGNED == ('"providerPacket": "%s"' % profile.NEW_PACKET).encode("ascii")


# The class table against the v5 model ---------------------------------------------------------------------------------

def _schema_with(change):
    schema = _load(profile.NP5_SCHEMA)
    change(schema["$defs"]["evidenceClasses"]["const"])
    return schema


def _models_for(schema):
    """This era's models, with the v5 model's schema pin moved to a mutated schema, so that a check over the mutated
    table reaches the rule it names rather than the model's schema pin."""
    m = profile.era_modules()
    m.np5.SCHEMA_SHA256 = m.np5.digest(m.np5.canonical(schema))
    return m


def _row_with(table, name, field):
    return next(row for row in table[name] if field in row["fields"])


def test_the_class_table_is_read_with_the_closed_grammar():
    schema, record_schema = _load(profile.NP5_SCHEMA), _load(profile.NP4_SCHEMA)
    assert profile.EVIDENCE_SCOPE in profile.validate_evidence_classes.__doc__
    admitted = profile.schema_admitted(record_schema)
    assert admitted == {"SERVER": [False, True], "OBSERVER": [False], "BROKER": [False], "WORKER": [False],
                        "EFFECT_GATE": [False]}
    table = schema["$defs"]["evidenceClasses"]["const"]
    named = [pair for text in table["captureTargets"].values() for pair in profile._target_pairs(text, admitted)]
    assert len(named) == 6
    # 63 exact capture paths (48 P1, 12 lifecycle, 3 backend; v4's P1 seal-label path is gone) and the 9 prose fields.
    exact, prose = profile.evidence_cells(table)
    counts = {name: len([row for row in exact if row[0] == name]) for name in profile.EVIDENCE_TABLES}
    assert counts == {"capture": 48, "lifecycleCapture": 12, "backendCapture": 3} and len(profile.PROSE_FIELDS) == 9
    assert sorted(field for _name, _number, field in prose) == sorted(profile.PROSE_FIELDS)
    assert dict(profile.ROLE_SCOPED_FIELDS) == {"cgroupFrozenBefore": ("WORKER",), "cgroupFrozenAfter": ("WORKER",)}
    assert set(profile.ROLE_SCOPED_FIELDS) <= {row[2] for row in exact if row[0] == "capture"}
    host = [row for row in exact if row[2] in profile.HOST_FIELDS[row[0]]]
    assert len(host) == 11 and all(not any(row[4].values()) for row in host)
    assert "hardeningObserved.sealMarker.selinuxLabel" not in {row[2] for row in exact}


@pytest.mark.parametrize("change, message", [
    ("role_moved", "capture_class decides the role's column: BROKER without CAP_NET_BIND_SERVICE, listed in OBSERVED_TARGET"),
    ("observer_moved", "capture_class decides the role's column: OBSERVER"),
    ("out_of_grammar_words", "captureTargets text outside the closed grammar or naming a capability set the schema "
                             "forbids: OBSERVED_TARGET"),
    ("role_twice", "the capture columns list every role and admitted capability set exactly once"),
    ("extra_table", "the capture columns are the fixed column-to-class map"),
    ("cell_changed", "check_capture refuses process.exe deleted for BROKER"),
    ("cell_marked_absent", "check_capture refuses process.uid added for SERVER"),
    ("host_cell_present", "check_capture refuses host deleted for SERVER"),
    ("lifecycle_host_present", "check_lifecycle_capture refuses booleansObserved deleted"),
    ("backend_host_present", "check_backend_capture refuses host deleted for APISERVER"),
    ("cell_out_of_grammar", "a class table row outside the closed grammar: capture row 1"),
    ("host_cell_out_of_grammar", "a class table row outside the closed grammar: capture row 8"),
    ("prose_unlisted", "a class table row outside the closed grammar: capture row 2"),
    ("prose_made_a_path", "the prose fields are exactly the listed ones")])
def test_a_changed_class_table_is_refused(monkeypatch, change, message):
    def edit(table):
        targets = table["captureTargets"]
        if change == "role_moved":
            targets["OBSERVED_TARGET"] = "EFFECT_GATE; BROKER; SERVER whose recorded capabilities exclude CAP_NET_BIND_SERVICE"
            targets["LABEL_BOUND_TARGET"] = "WORKER; SERVER whose recorded capabilities include CAP_NET_BIND_SERVICE"
        elif change == "observer_moved":
            targets["OBSERVED_TARGET"] = "OBSERVER; SERVER whose recorded capabilities exclude CAP_NET_BIND_SERVICE"
            targets["OBSERVER_OWN"] = "EFFECT_GATE (its own capture)"
        elif change == "out_of_grammar_words":
            targets["OBSERVED_TARGET"] = "EFFECT_GATE; SERVER unless CAP_NET_BIND_SERVICE is recorded"
        elif change == "role_twice":
            targets["LABEL_BOUND_TARGET"] = "WORKER; " + targets["LABEL_BOUND_TARGET"]
        elif change == "extra_table":
            table["hostCapture"] = []
        elif change == "cell_changed":
            _row_with(table, "capture", "process.exe")["LABEL_BOUND_TARGET"] = "LABEL_BOUND"
        elif change == "cell_marked_absent":
            _row_with(table, "capture", "process.uid")["OBSERVED_TARGET"] = "OBSERVED (absent)"
        elif change == "host_cell_present":
            row = _row_with(table, "capture", "host")
            row["OBSERVED_TARGET"] = row["LABEL_BOUND_TARGET"] = row["OBSERVER_OWN"] = "OUT_OF_SCOPE_HOST"
        elif change == "lifecycle_host_present":
            _row_with(table, "lifecycleCapture", "booleansObserved")["class"] = "OUT_OF_SCOPE_HOST"
        elif change == "backend_host_present":
            _row_with(table, "backendCapture", "host")["class"] = "OUT_OF_SCOPE_HOST"
        elif change == "cell_out_of_grammar":
            _row_with(table, "capture", "process.exe")["OBSERVER_OWN"] = "DECLARED_T04 (not captured)"
        elif change == "host_cell_out_of_grammar":
            _row_with(table, "capture", "host")["OBSERVER_OWN"] = "OUT_OF_SCOPE_HOST (record-only)"
        elif change == "prose_unlisted":
            fields = _row_with(table, "capture", "process.uid")["fields"]
            fields[fields.index("cgroupMembers[] (process fields)")] = "cgroupMembers[] (some process fields)"
        elif change == "prose_made_a_path":
            fields = _row_with(table, "capture", "bpfPrograms.*.pinLabel")["fields"]
            fields[fields.index("bpfPrograms.*.pinLabel")] = "bpfPrograms.pinLabel"
    schema = _schema_with(edit)
    _rebind(monkeypatch, {profile.NP5_SCHEMA: _dump(schema)})
    with pytest.raises(ValueError, match=re.escape("evidenceClasses against the model: " + message)):
        profile.validate_evidence_classes(_models_for(schema))


def _forgive_added(original, field, subjects):
    """A model check that strips the field from a capture of the named roles or components before checking it."""
    path = profile._capture_path(field)

    def forgiving(record, capture, *args):
        if (subjects is None or capture.get("role", capture.get("component")) in subjects) and profile._has(capture, path):
            capture = profile._probe(capture, path, None, True)
        return original(record, capture, *args)
    return forgiving


def _forgive_deleted(original, field, subjects):
    """A model check that accepts a capture of the named roles missing the field."""
    path = profile._capture_path(field)

    def forgiving(record, capture, *args):
        if (subjects is None or capture.get("role", capture.get("component")) in subjects) and not profile._has(capture, path):
            return None
        return original(record, capture, *args)
    return forgiving


@pytest.mark.parametrize("role, field", [("SERVER", "host"), ("OBSERVER", "selinuxBefore"), ("BROKER", "selinuxAfter"),
                                         ("WORKER", "kernelPolicyDigest"), ("EFFECT_GATE", "booleansObserved"),
                                         ("SERVER", "hardeningObserved"), ("OBSERVER", "bootEntryObserved")])
def test_a_capture_carrying_a_host_field_must_be_refused(role, field):
    """A model that accepts one dropped host field on one role's capture: the probe that adds it is no longer refused."""
    m = profile.era_modules()
    m.np5.check_capture = _forgive_added(m.np5.check_capture, field, (role,))
    with pytest.raises(ValueError, match=re.escape("evidenceClasses against the model: check_capture refuses %s added for %s"
                                                   % (field, role))):
        profile.validate_evidence_classes(m)


@pytest.mark.parametrize("check, field, message", [
    ("check_lifecycle_capture", "host", "check_lifecycle_capture refuses host added"),
    ("check_lifecycle_capture", "bootEntryObserved", "check_lifecycle_capture refuses bootEntryObserved added"),
    ("check_backend_capture", "host", "check_backend_capture refuses host added for APISERVER")])
def test_a_lifecycle_or_backend_capture_carrying_a_host_field_must_be_refused(check, field, message):
    m = profile.era_modules()
    setattr(m.np5, check, _forgive_added(getattr(m.np5, check), field, None))
    with pytest.raises(ValueError, match=re.escape("evidenceClasses against the model: " + message)):
        profile.validate_evidence_classes(m)


@pytest.mark.parametrize("role, field", [("SERVER", "process.exe"), ("EFFECT_GATE", "executableMaps"),
                                         ("SERVER", "pidsCurrent"), ("EFFECT_GATE", "deadlineMs")])
def test_a_p1_deletion_probe_whose_refusal_disappears_is_refused(role, field):
    m = profile.era_modules()
    m.np5.check_capture = _forgive_deleted(m.np5.check_capture, field, ("SERVER", "EFFECT_GATE"))
    with pytest.raises(ValueError, match=re.escape("evidenceClasses against the model: check_capture refuses %s deleted for "
                                                   % field)):
        profile.validate_evidence_classes(m)


@pytest.mark.parametrize("role, field", [("OBSERVER", "executableMaps"), ("BROKER", "process.exe"),
                                         ("SERVER", "process.rlimitCore"), ("SERVER", "files[].entry.selinuxLabel")])
def test_a_p1_addition_probe_whose_refusal_disappears_is_refused(role, field):
    m = profile.era_modules()
    m.np5.check_capture = _forgive_added(m.np5.check_capture, field, (role,))
    with pytest.raises(ValueError, match=re.escape("evidenceClasses against the model: check_capture refuses %s added for %s"
                                                   % (field, role))):
        profile.validate_evidence_classes(m)


@pytest.mark.parametrize("scoped", [
    {"cgroupFrozenBefore": ("WORKER",), "cgroupFrozenAfter": ("WORKER",), "runFsType": ("WORKER",)},
    {"cgroupFrozenBefore": ("WORKER",), "cgroupFrozenAfter": ("WORKER", "KUBELET")}])
def test_the_role_scoped_fields_are_exact_p1_paths_of_known_roles(monkeypatch, scoped):
    """A role-scoped field that is not an exact P1 path (runFsType is a lifecycle path), or a role outside the capture
    roles, is refused before any probe."""
    monkeypatch.setattr(profile, "ROLE_SCOPED_FIELDS", MappingProxyType(scoped))
    with pytest.raises(ValueError, match=re.escape("evidenceClasses against the model: the role-scoped fields are exact "
                                                   "P1 paths of known roles")):
        profile.validate_evidence_classes(profile.era_modules())


@pytest.mark.parametrize("scoped", [{"cgroupFrozenBefore": (), "cgroupFrozenAfter": ("WORKER",)},
                                    {"cgroupFrozenBefore": ("WORKER",), "cgroupFrozenAfter": ()}])
def test_every_role_scoped_field_is_probed_on_its_roles_captures(monkeypatch, scoped):
    """A role-scoped field scoped to no role is skipped on every capture, so its probe count stays 0 and the check
    refuses before any probe refusal."""
    monkeypatch.setattr(profile, "ROLE_SCOPED_FIELDS", MappingProxyType(scoped))
    with pytest.raises(ValueError, match=re.escape("evidenceClasses against the model: every role-scoped field is probed "
                                                   "on its roles' captures")):
        profile.validate_evidence_classes(profile.era_modules())


def test_the_frozen_bracket_is_probed_on_the_worker_captures_only(monkeypatch):
    monkeypatch.setattr(profile, "ROLE_SCOPED_FIELDS", MappingProxyType({}))
    with pytest.raises(ValueError, match=re.escape("evidenceClasses against the model: check_capture refuses "
                                                   "cgroupFrozenBefore deleted for SERVER")):
        profile.validate_evidence_classes(profile.era_modules())


@pytest.mark.parametrize("check, message", [
    ("check_capture", "check_capture accepts the positive capture: SERVER"),
    ("check_lifecycle_capture", "check_lifecycle_capture accepts the positive lifecycle capture"),
    ("check_backend_capture", "check_backend_capture accepts the positive backend capture: APISERVER")])
def test_a_model_that_refuses_a_positive_capture_is_refused(check, message):
    m = profile.era_modules()

    def refusing(*args):
        raise ValueError("refused")
    setattr(m.np5, check, refusing)
    with pytest.raises(ValueError, match=re.escape("evidenceClasses against the model: " + message)):
        profile.validate_evidence_classes(m)


def test_a_model_that_moves_a_role_is_refused():
    m = profile.era_modules()
    m.np5.capture_class = lambda record, role: "OBSERVED"
    with pytest.raises(ValueError, match=re.escape("evidenceClasses against the model: capture_class decides the role's "
                                                   "column: BROKER")):
        profile.validate_evidence_classes(m)


def test_the_eight_host_rows_name_exactly_the_four_proofs():
    m = profile.era_modules()
    assert profile.validate_host_rows(m, _status()) is None
    table = _load(profile.NP5_SCHEMA)["$defs"]["evidenceClasses"]["const"]
    rows = [row for name in profile.EVIDENCE_TABLES for row in table[name]
            if profile.HOST_CELL in [row.get(column) for column in profile.EVIDENCE_COLUMNS] + [row.get("class")]]
    assert len(rows) == 8 and sorted({row["proofs"][0] for row in rows}) == sorted(profile.HOST_PROOFS)
    assert dict(m.np5.HOST_FIELDS) == dict(profile.HOST_FIELDS)


@pytest.mark.parametrize("change, message", [
    ("proof_changed", "the backendCapture host rows hold exactly the dropped fields, each row its fields' one proof"),
    ("proof_added", "the capture host rows hold exactly the dropped fields, each row its fields' one proof"),
    ("field_moved", "the capture host rows hold exactly the dropped fields, each row its fields' one proof"),
    ("lifecycle_row_dropped", "the lifecycleCapture host rows hold exactly the dropped fields, each row its fields' one proof"),
    ("mixed_cells", "the capture host rows hold exactly the dropped fields, each row its fields' one proof"),
    ("status_proofs", "the eight host rows name exactly the four proofs of hostProofs"),
    ("model_fields", "the dropped fields are the model's")])
def test_a_changed_host_row_is_refused(monkeypatch, change, message):
    status = _status()
    m = profile.era_modules()

    def edit(table):
        if change == "proof_changed":
            _row_with(table, "backendCapture", "host")["proofs"] = ["T04-HOST-LOCKS"]
        elif change == "proof_added":
            _row_with(table, "capture", "host")["proofs"].append("T04-POLICY-STABLE")
        elif change == "field_moved":
            _row_with(table, "capture", "host")["fields"].append("deadlineMs")
        elif change == "lifecycle_row_dropped":
            table["lifecycleCapture"] = [row for row in table["lifecycleCapture"] if row["fields"] != ["booleansObserved"]]
        elif change == "mixed_cells":
            _row_with(table, "capture", "bootEntryObserved")["OBSERVER_OWN"] = "DECLARED_T04 (absent)"
    if change == "status_proofs":
        status["hostProofs"][3]["proof"] = "T04-BOOT"
    elif change == "model_fields":
        m.np5.HOST_FIELDS = dict(m.np5.HOST_FIELDS, backendCapture=("host", "observedAt"))
    else:
        _rebind(monkeypatch, {profile.NP5_SCHEMA: _dump(_schema_with(edit))})
    with pytest.raises(ValueError, match=re.escape("evidenceClasses against the model: " + message)):
        profile.validate_host_rows(m, status)


# The v5 model, executed from this era's bytes -------------------------------------------------------------------------

def test_the_models_are_executed_from_this_eras_bytes(monkeypatch):
    built = []
    original = profile._era_model

    def recorded(path, name, imports=None):
        built.append((path, name, sorted(imports or {})))
        return original(path, name, imports)
    monkeypatch.setattr(profile, "_era_model", recorded)
    m = profile.era_modules()
    assert built == [(profile.NP4_MODEL, "_met_enforce_038_native_qualification_v4", []),
                     (profile.NP5_MODEL, "_met_enforce_038_native_qualification_v5", ["native_qualification_v4"])]
    from scripts import native_qualification_v4 as installed
    assert m.np5.v4 is m.np4 and m.np5.v4 is not installed and m.np5.require is m.np4.require
    assert m.np5.__name__ == "_met_enforce_038_native_qualification_v5"


def test_the_v5_model_must_import_this_eras_v4_model(monkeypatch):
    original = profile._era_model

    def detached(path, name, imports=None):
        return original(path, name, None) if path == profile.NP5_MODEL else original(path, name, imports)
    monkeypatch.setattr(profile, "_era_model", detached)
    with pytest.raises(ValueError, match="native-profile v5 runs this era's native-profile v4 model"):
        profile.era_modules()


def test_the_replay_gets_exactly_the_pinned_inputs_from_verified_bytes():
    m = profile.era_modules()
    seen = {}
    m.np5.check_vectors = lambda vectors, files: seen.setdefault("np5", (vectors, files)) and profile.NP5_CHECKS
    profile.replay_model(m)
    vectors, files = seen["np5"]
    assert vectors == _load(profile.NP5_VECTORS)
    assert set(files) == set(profile.NP5_INPUTS.values()) | {profile.NP5_SCHEMA}
    assert all(raw == profile.reviewed_bytes(path) for path, raw in files.items())


@pytest.mark.parametrize("attribute, replacement", [
    ("check_vectors", lambda vectors, files: 283),
    ("check_vectors", lambda vectors, files: (_ for _ in ()).throw(ValueError("weakened"))),
    ("V5_INPUTS", {}), ("SCHEMA_PATH", "architecture/native-profile-v4/qualification.schema.json"),
    ("VECTOR_COUNTS", {"positive": 5, "negative": 265, "accepted": 7, "crossVersion": 6})])
def test_a_weakened_model_is_refused_by_the_validator(attribute, replacement):
    m = profile.era_modules()
    setattr(m.np5, attribute, replacement)
    message = ("native-profile v5 replays every vector over its pinned inputs" if attribute == "check_vectors"
               else "the model's pinned inputs and the vectors' counts")
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.replay_model(m)


def test_the_vector_counts_are_restated(monkeypatch):
    monkeypatch.setattr(profile, "NP5_COUNTS", dict(profile.NP5_COUNTS, negative=265))
    with pytest.raises(ValueError, match="the model's pinned inputs and the vectors' counts"):
        profile.replay_model(profile.era_modules())


def test_a_changed_vector_is_refused_by_the_replay(monkeypatch):
    vectors = _load(profile.NP5_VECTORS)
    vectors["negative"][0]["refusal"] = "a different refusal"
    _rebind(monkeypatch, {profile.NP5_VECTORS: _dump(vectors)})
    with pytest.raises(ValueError, match="native-profile v5 replays every vector over its pinned inputs"):
        profile.replay_model(profile.era_modules())


def test_a_changed_v4_vector_input_is_refused_by_the_replay(monkeypatch):
    path = profile.NP4_VECTORS
    _rebind(monkeypatch, {path: profile.reviewed_bytes(path) + b"\n"})
    with pytest.raises(ValueError, match="native-profile v5 replays every vector over its pinned inputs"):
        profile.replay_model(profile.era_modules())


# Projection and reads -------------------------------------------------------------------------------------------------

def test_a_later_successor_leaves_this_era_valid_through_projection(monkeypatch):
    original, reviewed = profile.regular_bytes, profile.reviewed_bytes
    paths = (profile.NP4_MODEL, profile.V6_EDGE, profile.STATUS_PATH)
    era = {path: reviewed(path) for path in paths}
    later = {path: era[path] + b"\n" for path in paths}
    monkeypatch.setattr(profile, "regular_bytes", lambda path: later.get(path) or original(path))
    with pytest.raises(ValueError):
        VALIDATE()
    monkeypatch.setattr(profile, "reviewed_bytes", lambda path: era[path] if path in later else reviewed(path))
    assert VALIDATE() is None
    tree = profile.reviewed_tree(profile.NP5_DIR)
    monkeypatch.setattr(profile, "reviewed_tree", lambda directory: {**tree, profile.NP5_DIR + "later.json": 0o100644})
    with pytest.raises(ValueError, match="holds exactly its files"):
        VALIDATE()


def test_reviewed_bytes_is_the_only_semantic_read():
    tree = ast.parse(profile.regular_bytes(profile.VALIDATOR_PATH))
    names = {"_verified", "_json", "_holds", "_bound", "_git_mode", "_texts", "_dump", "_era_import", "_era_model",
             "era_modules", "validate_freeze", "validate_contract_files", "candidate_status", "validate_adoption",
             "validate_source_index", "validate_edge_record_v7", "_evidence_message", "schema_admitted",
             "_target_pairs", "_capture_path", "_cell_present", "evidence_cells", "_has", "_at", "_declared", "_probe",
             "validate_host_rows", "validate_evidence_classes", "replay_model", "validate_native_profile_v5"}
    seen = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            seen.add(node.name)
            used = {name.id for name in ast.walk(node) if isinstance(name, ast.Name)}
            attributes = {attribute.attr for attribute in ast.walk(node) if isinstance(attribute, ast.Attribute)}
            assert not used & {"regular_bytes", "open"}, node.name
            assert not attributes & {"read_bytes", "read_text", "open", "lstat", "stat", "iterdir", "glob", "rglob"}, node.name
    assert seen == names


def test_the_check_reads_no_unverified_byte(monkeypatch):
    """Every byte the check uses comes through reviewed_bytes: with those served from memory, the authority the generic
    layer checked served as checked, and every other file read refused, the whole check still holds (the models read
    nothing themselves; their library imports load first)."""
    profile.era_modules()
    paths = set(profile.ERA_SHA256) | set(profile._PROJECTION_RULES)
    served = {path: profile.reviewed_bytes(path) for path in paths}
    record = profile.authority()
    monkeypatch.setattr(profile, "reviewed_bytes", lambda target: served[target])
    monkeypatch.setattr(profile, "authority", lambda: record)

    def refused(*args, **kwargs):
        raise AssertionError("unverified read: %r" % (args[:1],))
    monkeypatch.setattr(Path, "read_bytes", refused)
    monkeypatch.setattr(Path, "read_text", refused)
    monkeypatch.setattr(Path, "open", refused)
    import builtins
    monkeypatch.setattr(builtins, "open", refused)
    assert VALIDATE() is None


def _line_hunks(after, before):
    import difflib
    current, previous = after.splitlines(keepends=True), before.splitlines(keepends=True)
    offsets = [0]
    for line in current:
        offsets.append(offsets[-1] + len(line))
    return tuple((offsets[a], b"".join(current[a:b]), b"".join(previous[c:d]))
                 for tag, a, b, c, d in difflib.SequenceMatcher(None, current, previous, autojunk=False).get_opcodes()
                 if tag != "equal")


def test_whole_line_hunks_are_refused_where_canonical_ones_differ(monkeypatch):
    rules = dict(profile._PROJECTION_RULES)
    path = next(path for path, rule in rules.items()
                if _line_hunks(profile.reviewed_bytes(path), profile._undo_this_layer(path, profile.reviewed_bytes(path)))
                != rule["reverseHunks"])
    after = profile.reviewed_bytes(path)
    before = profile._undo_this_layer(path, after)
    line = _line_hunks(after, before)
    assert profile._inverse(after, line) == before
    rules[path] = MappingProxyType(dict(rules[path], reverseHunks=line))
    monkeypatch.setattr(profile, "_PROJECTION_RULES", MappingProxyType(rules))
    with pytest.raises(ValueError, match=re.escape("canonical byte-minimal inverse hunks: " + path)):
        profile.validate_canonical_hunks()


def test_every_recorded_hunk_is_canonical_and_reconstructs():
    for path, rule in profile._PROJECTION_RULES.items():
        after = profile.reviewed_bytes(path)
        before = profile._undo_this_layer(path, after)
        hunks = profile.canonical_hunks(after, before)
        assert hunks == rule["reverseHunks"] and profile._inverse(after, hunks) == before
        prior_end = -1
        for at, removed, inserted in hunks:
            assert at > prior_end and removed != inserted
            assert not (removed and inserted and (removed[0] == inserted[0] or removed[-1] == inserted[-1]))
            prior_end = at + len(removed)
