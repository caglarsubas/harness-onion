"""Exact source lineage for MET-LIVE-002; the probe-kit scope amendment with the review-record brief registry rider: the head keeps the full fan-in (8 own and 71 predecessor routes, every catalog walk and round trip, the full payload loop), and the semantic check (the freeze, the files added, the adoption with its five reviews and redacted briefs, the registry and its rider, the reference model over the record's base bytes read git-free, and the canonical hunks) has a failing case for every refusal, each on plain data; the git-free base reads are compared with `git show` at the record's base."""
import ast
import json
from copy import deepcopy
import os
import re
import stat
import subprocess
from pathlib import Path
from types import MappingProxyType

import pytest

from scripts import validate_probe_kit_scope as profile
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
    # The newer MET-GOV-003 layer is projected away before this layer's payload checks.
    return profile.successor.historical_catalog(packets())


def changed_test():
    return next(path for path in profile._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert profile.validate() is None
    current = packets()
    accepted = profile.historical_catalog(current)
    assert len(current) == 273 and len(accepted) == 259
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


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "rrv_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = profile.historical_bytes(path, raw) if route in ("current_test", "old_bytes") else None
    current_packets = packets() if route == "catalog" else None
    layer = layer_packets() if route == "payloads" else None
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
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
    with pytest.raises(ValueError, match="probe kit scope history authority digest"):
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
    assert len(profile.historical_catalog(current)) == 259


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
    assert len(profile.historical_catalog(current)) == 259
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
    assert len(rules) == 260 and len(parsed) == 259
    assert profile._packet_rules() is rules and len(parsed) == 259
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
    with pytest.raises(ValueError, match="probe kit scope history authority digest"):
        profile.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = layer_packets()
    profile.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "probe-kit-scope-authority.json").write_bytes(
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
    # The newer MET-GOV-003 layer refuses a mutated validator before this layer.
    with pytest.raises(ValueError, match="unreviewed current source: scripts/validate_probe_kit_scope.py"):
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
            assert all("validate_" not in alias.name or alias.name == "validate_linux_probe_kit_gate"
                       for alias in node.names)


def _count_authority_reads(monkeypatch):
    counts = {}
    for module in (profile.successor, profile, rrv, pod, evs, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner):
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
    expected = {module.__name__: 1 for module in (profile.successor, profile, rrv, pod, evs, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner)}
    if route == "current_test":
        # The forward route reads this layer's newest bytes and then projects them forward once more.
        assert all(counts[name] >= 1 for name in expected) and set(counts) == set(expected)
    else:
        assert counts == expected


# MET-LIVE-002 (LINUX-PROBE-KIT-SCOPE, LPK-0): this era's check, and a failing case for every check. Every mutant below is
# applied to plain data handed to the layer's pure checks: nothing in the layer or the library is patched or swapped. The
# mutants are built by the pure helpers _<area>_mutant(change), one change name per mutant. The layer reads the record's
# base bytes git-free (MON-260-READ (a)); test_the_git_free_base_reads_equal_git_show_at_the_record_base compares them
# with `git show <record base>:<path>` (BUILD_RULES S3-17), the only git read of this layer and its test.

VALIDATE = profile.validate_probe_kit_scope
# Tamper values name paths that already exist and that this packet does not carry in the tampered place.
OTHER_PATH = "scripts/validate_review_record.py"
_CACHE = {}


def _status():
    return json.loads(profile._verified(profile.STATUS_PATH))


def _record():
    return json.loads(profile._verified(profile.AMENDMENT_PATH))


def _rules():
    return json.loads(profile._verified(profile.PREDECESSOR_AUTHORITY))["changedFiles"]


def _reads():
    """The git-free base reads, built once per module through the layer's own functions (the layer itself reads them
    afresh on every validate)."""
    if "reads" not in _CACHE:
        rules = _rules()
        _CACHE["reads"] = {path: profile.base_bytes(path, profile.reviewed_bytes(path), rules.get(path))
                           for path in sorted(profile.recorded_sha256(_record()))}
    return _CACHE["reads"]


def _changed():
    record = profile.authority()
    return sorted(set(record["changedFiles"]) | set(record["newFiles"])
                  | {profile.AUTHORITY_PATH, profile.VALIDATOR_PATH, profile.PACKET_PATH})


def _gate():
    return profile.era_models()[1].check(json.loads(profile._verified(profile.SURFACE_RECORD)))["gateMaterial"]


def _flip(text):
    """A different lowercase hex digest of the same length."""
    return text[:-1] + ("0" if text[-1] != "0" else "1")


def test_the_contract_holds_for_this_era():
    assert VALIDATE() is None


def test_the_era_holds_the_added_files_the_registry_the_surface_and_259s_authority():
    assert set(profile.ERA_SHA256) == set(profile.NEW_FILES) | {profile.REGISTRY_PATH, profile.SURFACE_RECORD,
                                                                profile.SURFACE_MODEL, profile.PREDECESSOR_AUTHORITY}
    assert len(profile.ERA_SHA256) == 25 and len(profile.NEW_FILES) == 21 and len(set(profile.NEW_FILES)) == 21
    assert profile.REGISTRY_RIDER == ("architecture/review-record/briefs.json",
                                      "architecture/review-briefs/REVIEW_BRIEF_PACKET.md",
                                      "architecture/review-briefs/REVIEW_BRIEF_CONTRACT.md")
    assert profile.RIDER_GATE_PATHS == ("architecture/review-record/briefs.json",)
    assert [row["record"] for row in _status()["reviews"]] == list(profile.HISTORY_RECORDS)
    assert [row["brief"] for row in _status()["reviews"]] == list(profile.HISTORY_BRIEFS)
    for path, expected in profile.ERA_SHA256.items():
        assert profile.digest(profile.reviewed_bytes(path)) == expected


@pytest.mark.parametrize("path", sorted(profile.ERA_SHA256))
def test_every_era_file_is_bound_by_digest(path):
    raw = profile._verified(path)
    assert profile._era_bytes(path, raw) == raw
    for changed in (raw + b" ", bytearray(raw)):
        with pytest.raises(ValueError, match=re.escape("unreviewed LINUX-PROBE-KIT-SCOPE source: " + path)):
            profile._era_bytes(path, changed)


def test_a_path_outside_the_era_is_refused_before_it_is_read():
    for path in (profile.CONTRACT_DIR + "/notes.md", profile.BRIEFS_DIR + "/REVIEW_BRIEF_DESIGN.md", OTHER_PATH,
                 profile.VALIDATOR_PATH, profile.HEAD_TEST, profile.LIVING_CATALOGS[0], None):
        with pytest.raises(ValueError, match="MET-LIVE-002 reviewed bytes are bound: "):
            profile._verified(path)
        with pytest.raises(ValueError, match="MET-LIVE-002 reviewed bytes are bound: "):
            profile._era_bytes(path, b"")


# The freeze and the files this packet adds -----------------------------------------------------------------------------

FREEZE = "this packet edits only chain validators, tests, the three living catalogs and the registry: "


@pytest.mark.parametrize("path", ["scripts/probe_kit_scope.py", "scripts/evolution_surface.py", "scripts/review_record.py",
                                  "scripts/chain_identity.py", "architecture/review-record/README.md",
                                  "architecture/evolution-surface/evolution-surface.json", "docs/DEVELOPMENT_STATUS.md",
                                  "docs/alpha-2/BROKER_HANDOFF_READINESS.md", "tests/conftest.py", "conftest.py",
                                  "scripts/validate_x/y.py", "scripts/validate_x.txt", "ci/linux-runner/runner.py",
                                  "pyproject.toml", None])
def test_the_freeze_refuses_every_other_change(path):
    changed = list(profile._PROJECTION_RULES)
    profile.check_freeze(changed)
    with pytest.raises(ValueError, match=re.escape(FREEZE)):
        profile.check_freeze(changed + [path])


def _added_mutant(change):
    added = list(profile.NEW_FILES) + [profile.HEAD_TEST]
    if change == "missing":
        added.remove(profile.STATUS_PATH)
    elif change == "extra":
        added.append(profile.BRIEFS_DIR + "/REVIEW_BRIEF_DESIGN.md")
    elif change == "duplicate":
        added.append(profile.MODEL_PATH)
    elif change == "no_head_test":
        added.remove(profile.HEAD_TEST)
    else:
        added = tuple(added)
    return added


@pytest.mark.parametrize("change", ["missing", "extra", "duplicate", "no_head_test", "not_list"])
def test_the_packet_adds_exactly_its_files_each_once(change):
    profile.check_new_files(list(profile.NEW_FILES) + [profile.HEAD_TEST])
    profile.check_new_files(list(profile.authority()["newFiles"]))
    with pytest.raises(ValueError, match="this packet adds exactly its contract files, model, page, oracle test, "
                                         "generic briefs and layer test, each once"):
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


# The adoption ----------------------------------------------------------------------------------------------------------

STATUS_CHANGES = ["schema", "work_item", "packet", "slot", "slot_text", "status", "base", "design", "reviewers", "note",
                  "oracle", "rider_path", "rider_entries", "slips", "non_claim", "extra_key", "missing_key", "key_order"]


def _status_mutant(change):
    status = _status()
    if change == "schema":
        status["schemaVersion"] = "planeon.internal.probe-kit-scope-status/v2"
    elif change == "work_item":
        status["workItem"] = "LINUX-PROBE-KIT-001"
    elif change == "packet":
        status["packet"] = "MET-LIVE-003"
    elif change == "slot":
        status["slot"] = 261
    elif change == "slot_text":
        status["slot"] = "260"
    elif change == "status":
        status["status"] = "ADOPTED_CONTRACT_CANDIDATE"
    elif change == "base":
        status["baseMain"] = "2043cc27883448e3ff030b7868110e295f32fe09"
    elif change == "design":
        status["design"]["sha256"] = _flip(status["design"]["sha256"])
    elif change == "reviewers":
        status["independentReviewers"] = "the author"
    elif change == "note":
        status["reviewHistoryNote"] += " They carry merge authority."
    elif change == "oracle":
        status["oracle"]["result"] = "409/410"
    elif change == "rider_path":
        status["registryRider"]["paths"].append(profile.BRIEFS_DIR + "/REVIEW_BRIEF_DESIGN.md")
    elif change == "rider_entries":
        status["registryRider"]["entries"].reverse()
    elif change == "slips":
        status["slips"].pop()
    elif change == "non_claim":
        status["nonClaims"][0] = status["nonClaims"][0].replace("DATA_CHECK_ONLY", "ACCEPTANCE")
    elif change == "extra_key":
        status["merged"] = True
    elif change == "missing_key":
        del status["nonClaims"]
    else:
        status = dict(reversed(list(status.items())))
    return status


@pytest.mark.parametrize("change", STATUS_CHANGES)
def test_the_status_is_closed_and_records_the_adoption(change):
    profile.check_status(_status())
    with pytest.raises(ValueError, match="adopted LINUX-PROBE-KIT-SCOPE status"):
        profile.check_status(_status_mutant(change))


def _adoptions_mutant(change):
    adoptions = deepcopy(_status()["adoptions"])
    if change == "drop_c11":
        adoptions.pop()
    elif change == "drop_c3":
        adoptions.pop(0)
    elif change == "reorder":
        adoptions[0], adoptions[1] = adoptions[1], adoptions[0]
    elif change == "check_digest":
        adoptions[-1]["adoptionCheckSha256"] = _flip(adoptions[-1]["adoptionCheckSha256"])
    elif change == "ruling":
        adoptions[2]["ruling"] = "MON-LPK0-ADOPT-C9"
    elif change == "extra_key":
        adoptions[0]["note"] = "x"
    elif change == "key_order":
        adoptions[0] = dict(reversed(list(adoptions[0].items())))
    else:
        adoptions.append(dict(adoptions[-1], candidate="c12"))
    return adoptions


@pytest.mark.parametrize("change", ["drop_c11", "drop_c3", "reorder", "check_digest", "ruling", "extra_key", "key_order",
                                    "c12"])
def test_the_adoptions_run_c3_to_c11_with_their_check_digests(change):
    profile.check_adoptions(_status()["adoptions"])
    with pytest.raises(ValueError, match="the adoptions run c3 to c11 with their rulings and ADOPTION_CHECK digests"):
        profile.check_adoptions(_adoptions_mutant(change))


def _files():
    return {path: profile._verified(path) for path in profile.ADOPTED_SUBJECT}


def _subject_mutant(change):
    subject = dict(_status()["adoptedSubject"])
    if change == "digest":
        subject[profile.README_PATH] = _flip(subject[profile.README_PATH])
    elif change == "missing":
        del subject[profile.REPLAY_PATH]
    elif change == "extra":
        subject[profile.STATUS_PATH] = "0" * 64
    else:
        subject = dict(reversed(list(subject.items())))
    return subject


@pytest.mark.parametrize("change", ["digest", "missing", "extra", "order"])
def test_status_names_the_adopted_subject_by_digest(change):
    profile.check_subject(_status()["adoptedSubject"], _files())
    with pytest.raises(ValueError, match="status.json names the adopted subject by digest"):
        profile.check_subject(_subject_mutant(change), _files())


@pytest.mark.parametrize("path", list(profile.ADOPTED_SUBJECT))
def test_the_adopted_files_are_the_adopted_subjects_bytes(path):
    files = _files()
    for changed in (files[path] + b"\n", None):
        with pytest.raises(ValueError, match=re.escape("the adopted files are the adopted subject's bytes: " + path)):
            profile.check_subject(_status()["adoptedSubject"], {**files, path: changed})


def test_the_layer_pins_the_adopted_amendment():
    raw = profile._verified(profile.AMENDMENT_PATH)
    profile.check_pin(raw)
    record = json.loads(raw)
    dropped = json.dumps(dict(record, staysTrue=record["staysTrue"][1:]), indent=1).encode("utf-8")
    for changed in (raw + b"\n", dropped, None):
        with pytest.raises(ValueError, match="the layer pins the adopted amendment.json"):
            profile.check_pin(changed)


def _lists_mutant(change):
    status = _status()
    if change == "review_missing":
        status["reviews"].pop()
    elif change == "redaction_missing":
        status["briefRedactions"].pop()
    elif change == "redaction_extra":
        status["briefRedactions"].append(status["briefRedactions"][0])
    else:
        status["reviews"] = tuple(status["reviews"])
    return status


@pytest.mark.parametrize("change", ["review_missing", "redaction_missing", "redaction_extra", "reviews_not_list"])
def test_every_review_and_redaction_is_recorded(change):
    profile.check_review_lists(_status())
    with pytest.raises(ValueError, match="every review and brief redaction is recorded"):
        profile.check_review_lists(_lists_mutant(change))


def _review_parts(number):
    return (_status()["reviews"][number - 1], profile._verified(profile.HISTORY_RECORDS[number - 1]),
            profile._verified(profile.HISTORY_BRIEFS[number - 1]))


def _review_mutant(number, change):
    row, record, brief = _review_parts(number)
    row = deepcopy(row)
    if change == "record_bytes":
        record = record + b" "
    elif change == "brief_bytes":
        brief = brief + b"\n"
    elif change == "row_digest":
        row["recordSha256"] = _flip(row["recordSha256"])
    elif change == "row_verdict":
        row["verdict"] = "PASS_FOR_ADOPTION" if row["verdict"] != "PASS_FOR_ADOPTION" else "CHANGES_REQUIRED"
    elif change == "row_path":
        row["record"] = profile.HISTORY_RECORDS[number % len(profile.HISTORY_RECORDS)]
    elif change == "key_order":
        row = dict(reversed(list(row.items())))
    elif change == "number":
        number = number % len(profile.HISTORY_RECORDS) + 1
    else:
        record = None
    return number, row, record, brief


@pytest.mark.parametrize("number", [1, 2, 3, 4, 5])
@pytest.mark.parametrize("change", ["record_bytes", "brief_bytes", "row_digest", "row_verdict", "row_path", "key_order",
                                    "number", "record_not_bytes"])
def test_each_review_is_bound_to_its_published_record_and_brief(number, change):
    profile.check_review(number, *_review_parts(number))
    with pytest.raises(ValueError, match=re.escape("a review is bound to its published record and brief: review ")):
        profile.check_review(*_review_mutant(number, change))


def _redaction_mutant(number, change):
    status = _status()
    row, redaction = status["reviews"][number - 1], deepcopy(status["briefRedactions"][number - 1])
    brief = profile._verified(profile.HISTORY_BRIEFS[number - 1])
    if change == "count":
        redaction["substitutions"][0]["count"] = 5
    elif change == "to":
        redaction["substitutions"][1]["to"] = "<tmp>/"
    elif change == "from_digest":
        redaction["substitutions"][0]["fromSha256"] = _flip(redaction["substitutions"][0]["fromSha256"])
    elif change == "published":
        redaction["publishedSha256"] = _flip(redaction["publishedSha256"])
    elif change == "reviewed":
        redaction["reviewedSha256"] = _flip(redaction["reviewedSha256"])
    elif change == "brief_path":
        redaction["brief"] = profile.HISTORY_BRIEFS[number % len(profile.HISTORY_BRIEFS)]
    elif change == "extra_key":
        redaction["note"] = "x"
    elif change == "extra_placeholder":
        brief = brief + b"\n<workspace>/x\n"
    else:
        redaction["substitutions"].pop()
    return number, redaction, row, brief


@pytest.mark.parametrize("number", [1, 2, 3, 4, 5])
@pytest.mark.parametrize("change", ["count", "to", "from_digest", "published", "reviewed", "brief_path", "extra_key",
                                    "extra_placeholder", "missing_substitution"])
def test_each_brief_redaction_is_as_stated(number, change):
    status = _status()
    profile.check_redaction(number, status["briefRedactions"][number - 1], status["reviews"][number - 1],
                            profile._verified(profile.HISTORY_BRIEFS[number - 1]))
    with pytest.raises(ValueError, match=re.escape("a brief redaction is as stated: brief %d" % number)):
        profile.check_redaction(*_redaction_mutant(number, change))


def _oracle_mutant(change):
    identity = json.loads(profile._verified(profile.ORACLE_IDENTITY_PATH))
    oracle, row = profile._verified(profile.ORACLE_TEST), _status()["oracle"]
    if change == "decision":
        identity["ruling"]["decision"] = "NONE_NEEDED"
    elif change == "ref":
        identity["ruling"]["ref"] = identity["ruling"]["ref"].replace("KEEP", "KEPT")
    elif change == "file_digest":
        identity["file"]["sha256"] = _flip(identity["file"]["sha256"])
    elif change == "file_path":
        identity["file"]["path"] = profile.HEAD_TEST
    elif change == "oracle_bytes":
        oracle = oracle + b"\n"
    elif change == "row_test":
        row["test"] = profile.HEAD_TEST
    elif change == "row_identity":
        row["identity"] = profile.STATUS_PATH
    elif change == "row_digest":
        row["sha256"] = _flip(row["sha256"])
    else:
        oracle = None
    return json.dumps(identity).encode("utf-8"), oracle, row


@pytest.mark.parametrize("change", ["decision", "ref", "file_digest", "file_path", "oracle_bytes", "row_test",
                                    "row_identity", "row_digest", "not_bytes"])
def test_the_oracle_identity_binds_the_oracle_file_with_keep(change):
    profile.check_oracle_identity(profile._verified(profile.ORACLE_IDENTITY_PATH), profile._verified(profile.ORACLE_TEST),
                                  _status()["oracle"])
    with pytest.raises(ValueError, match="the oracle identity binds the oracle file, with ruling KEEP"):
        profile.check_oracle_identity(*_oracle_mutant(change))


# The registry rider ----------------------------------------------------------------------------------------------------

REGISTRY_MESSAGE = "the registry is the base's with exactly the five ruled entries appended, each pinning its brief"


def _registry_parts():
    raw = profile._verified(profile.REGISTRY_PATH)
    return raw, profile._undo_this_layer(profile.REGISTRY_PATH, raw), {
        path: profile._verified(path) for path in (profile.PACKET_BRIEF, profile.CONTRACT_BRIEF)}


def _registry_mutant(change):
    raw, base, briefs = _registry_parts()
    registry = json.loads(raw)
    if change == "base_bytes":
        base = base + b"\n"
    elif change == "brief_bytes":
        briefs = {**briefs, profile.PACKET_BRIEF: briefs[profile.PACKET_BRIEF] + b"\n"}
    elif change == "missing_entry":
        registry["briefs"].pop()
    elif change == "extra_entry":
        registry["briefs"].append(dict(registry["briefs"][-2], series="MET-LIVE-003/contract"))
    elif change == "entry_order":
        registry["briefs"][-1], registry["briefs"][-2] = registry["briefs"][-2], registry["briefs"][-1]
    elif change == "entry_digest":
        registry["briefs"][-1]["sha256"] = _flip(registry["briefs"][-1]["sha256"])
    elif change == "entry_version":
        registry["briefs"][-1]["version"] = 2
    elif change == "entry_path":
        registry["briefs"][-2]["path"] = "architecture/review-record/REVIEW_BRIEF_PACKET.md"
    elif change == "base_entry":
        registry["briefs"][0]["version"] = 2
    elif change == "kinds":
        del registry["kinds"]["DESIGN"]
    else:
        registry["schemaVersion"] = "planeon.review-briefs/v2"
    if change not in ("base_bytes", "brief_bytes"):
        raw = json.dumps(registry, indent=1).encode("utf-8")
    return raw, base, briefs


@pytest.mark.parametrize("change", ["base_bytes", "brief_bytes", "missing_entry", "extra_entry", "entry_order",
                                    "entry_digest", "entry_version", "entry_path", "base_entry", "kinds", "schema"])
def test_the_registry_is_the_base_with_exactly_the_five_ruled_entries(change):
    profile.check_registry(*_registry_parts())
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


RIDER = "the registry rider is among the changed files, and briefs.json is exactly the gate path among them"


def _rider_mutant(change):
    changed = _changed()
    if change == "no_registry":
        changed.remove(profile.REGISTRY_PATH)
    elif change == "no_packet_brief":
        changed.remove(profile.PACKET_BRIEF)
    elif change == "no_contract_brief":
        changed.remove(profile.CONTRACT_BRIEF)
    elif change == "gate_path":
        changed.append("architecture/review-record/README.md")
    elif change == "gate_prefix":
        changed.append("docs/harnesses/x.md")
    elif change == "case_variant":
        changed.append("Architecture/Evolution-Surface/README.md")
    else:
        changed.append("schemas/x.schema.json")
    return changed


@pytest.mark.parametrize("change", ["no_registry", "no_packet_brief", "no_contract_brief", "gate_path", "gate_prefix",
                                    "case_variant", "schema"])
def test_the_registry_rider_and_its_one_gate_path(change):
    changed, gate = _changed(), _gate()
    profile.check_rider(changed, gate)
    assert profile.gate_paths(gate, changed) == [profile.REGISTRY_PATH]
    assert profile.gate_paths(gate, [path for path in changed if path not in profile.REGISTRY_RIDER]) == []
    with pytest.raises(ValueError, match=RIDER):
        profile.check_rider(_rider_mutant(change), gate)


# The record's base bytes, read git-free (MON-260-READ (a)), and the reference model ------------------------------------

def test_one_recorded_sha256_per_path():
    record = _record()
    recorded = profile.recorded_sha256(record)
    assert len(recorded) == profile.RECORDED_PATHS == 279
    row = record["supersedes"][0]
    assert row["path"] in {item["path"] for item in record["inventory"]["files"]}
    record["supersedes"][0] = dict(row, sha256=_flip(row["sha256"]))
    with pytest.raises(ValueError, match=re.escape("one recorded sha256 per path: " + row["path"])):
        profile.recorded_sha256(record)


def _living_mutant(change):
    rules, recorded = dict(_rules()), dict(profile.recorded_sha256(_record()))
    if change == "extra_path":
        rules[_record()["supersedes"][0]["path"]] = {}
    elif change == "missing_catalog":
        del rules[profile.LIVING_CATALOGS[0]]
    else:
        del recorded[sorted(set(recorded) - set(profile.LIVING_CATALOGS))[0]]
    return rules, recorded


@pytest.mark.parametrize("change", ["extra_path", "missing_catalog", "fewer_recorded"])
def test_the_recorded_paths_259_changed_are_the_living_catalogs(change):
    profile.check_living(_rules(), profile.recorded_sha256(_record()))
    with pytest.raises(ValueError, match="the recorded paths 259 changed are exactly the three living catalogs"):
        profile.check_living(*_living_mutant(change))


def _rebuild_mutant(path, change):
    rule = deepcopy(_rules()[path])
    if change == "after":
        rule["afterSha256"] = _flip(rule["afterSha256"])
    elif change == "before":
        rule["beforeSha256"] = _flip(rule["beforeSha256"])
    elif change == "hunk":
        rule["reverseHunks"][0]["at"] += 1
    elif change == "hunk_encoding":
        rule["reverseHunks"][0]["insertBase64"] = "!!"
    else:
        del rule["reverseHunks"]
    return path, profile.reviewed_bytes(path), rule


@pytest.mark.parametrize("path", profile.LIVING_CATALOGS)
@pytest.mark.parametrize("change", ["after", "before", "hunk", "hunk_encoding", "missing_key"])
def test_the_living_catalogs_are_rebuilt_to_their_base_bytes(path, change):
    rule = _rules()[path]
    rebuilt = profile.base_bytes(path, profile.reviewed_bytes(path), rule)
    assert profile.digest(rebuilt) == rule["beforeSha256"] == profile.recorded_sha256(_record())[path]
    with pytest.raises(ValueError, match=re.escape("a living catalog is rebuilt to its base bytes: " + path)):
        profile.base_bytes(*_rebuild_mutant(path, change))


def _reads_mutant(change):
    reads, path = dict(_reads()), profile.LIVING_CATALOGS[0]
    if change == "missing":
        del reads[path]
    elif change == "extra":
        reads["README.md"] = b""
    elif change == "changed":
        reads[path] = reads[path] + b"\n"
    else:
        reads[path] = None
    return reads


@pytest.mark.parametrize("change, message", [
    ("missing", "every recorded path is read once"), ("extra", "every recorded path is read once"),
    ("changed", "the recorded base bytes are bound: "), ("not_bytes", "the recorded base bytes are bound: ")])
def test_the_base_reads_are_bound_by_the_record(change, message):
    recorded = profile.recorded_sha256(_record())
    profile.check_base_reads(recorded, dict(_reads()))
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.check_base_reads(recorded, _reads_mutant(change))


def test_the_git_free_base_reads_equal_git_show_at_the_record_base():
    """MON-260-READ (a) and BUILD_RULES S3-17: the layer reads the record's base bytes git-free; this test, the only git
    reader of this layer and its test, compares every recorded path with `git show <record base>:<path>`. It needs the
    record base's objects in the clone; the pre-check runs it inside the signed offline tree and records its seconds."""
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0")
    reads = _reads()
    assert len(reads) == profile.RECORDED_PATHS and sum(len(raw) for raw in reads.values()) > 60_000_000
    for path in sorted(reads):
        shown = subprocess.run(["git", "-C", str(profile.ROOT), "show", "%s:%s" % (profile.RECORD_BASE, path)],
                               capture_output=True, env=env)
        assert shown.returncode == 0, "git show %s:%s failed: %r" % (profile.RECORD_BASE[:8], path, shown.stderr[-200:])
        assert shown.stdout == reads[path], path


def test_the_era_models_are_executed_from_verified_bytes():
    model, surface = profile.era_models()
    assert model.__name__ == "_met_live_002_probe_kit_scope" and surface.__name__ == "_met_live_002_evolution_surface"
    assert model.BASE == profile.RECORD_BASE and model.__file__ == str(profile.ROOT / profile.MODEL_PATH)


def test_the_model_returns_no_refusal_and_each_scope_mutant_is_refused():
    """The model, from this era's bytes, over the git-free base reads: no refusal with the changed files less the rider;
    a pinned, quoted, amended or cross-input path among the changed files (S3-7, case-folded by the model) or a gate
    path is refused."""
    model = profile.era_models()[0]
    record, reads, gate = _record(), _reads(), _gate()
    scope = [path for path in _changed() if path not in profile.REGISTRY_RIDER]
    assert profile.gate_paths(gate, scope) == []
    profile.check_model(model.check(record, reads.get, scope, []))
    for path in (record["notAmended"]["pinned"][0]["path"], record["supersedes"][0]["path"], record["amends"][0]["path"],
                 record["crossInputs"][0]["path"], record["supersedes"][0]["path"].upper()):
        refusals = model.check(record, reads.get, scope + [path], [])
        assert model.R["pinned"] in refusals, path
        with pytest.raises(ValueError, match="the reference model returns no refusal for the adopted record"):
            profile.check_model(refusals)
    refusals = model.check(record, reads.get, scope + [profile.REGISTRY_PATH], [profile.REGISTRY_PATH])
    assert model.R["gate"] in refusals
    for value in (refusals, None, ["x"], ()):
        with pytest.raises(ValueError, match="the reference model returns no refusal for the adopted record"):
            profile.check_model(value)


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
                      "check_adoptions", "check_subject", "check_pin", "check_review_lists", "check_review",
                      "check_redaction", "check_oracle_identity", "check_registry", "check_gate_list", "check_rider",
                      "recorded_sha256", "check_living", "base_bytes", "check_base_reads", "check_model"}
CHECK_TESTS = {
    "MET-LIVE-002 reviewed bytes are bound: ": "test_a_path_outside_the_era_is_refused_before_it_is_read",
    "unreviewed LINUX-PROBE-KIT-SCOPE source: ": "test_every_era_file_is_bound_by_digest",
    FREEZE: "test_the_freeze_refuses_every_other_change",
    "this packet adds exactly its contract files, model, page, oracle test, generic briefs and layer test, each once":
        "test_the_packet_adds_exactly_its_files_each_once",
    "a file this packet adds is a regular file of git mode 100644: ":
        "test_an_added_file_is_a_regular_file_of_mode_100644_without_a_local_path",
    "no absolute local path in a file this packet adds: ":
        "test_an_added_file_is_a_regular_file_of_mode_100644_without_a_local_path",
    "adopted LINUX-PROBE-KIT-SCOPE status": "test_the_status_is_closed_and_records_the_adoption",
    "the adoptions run c3 to c11 with their rulings and ADOPTION_CHECK digests":
        "test_the_adoptions_run_c3_to_c11_with_their_check_digests",
    "status.json names the adopted subject by digest": "test_status_names_the_adopted_subject_by_digest",
    "the adopted files are the adopted subject's bytes: ": "test_the_adopted_files_are_the_adopted_subjects_bytes",
    "the layer pins the adopted amendment.json": "test_the_layer_pins_the_adopted_amendment",
    "every review and brief redaction is recorded": "test_every_review_and_redaction_is_recorded",
    "a review is bound to its published record and brief: review ":
        "test_each_review_is_bound_to_its_published_record_and_brief",
    "a brief redaction is as stated: brief ": "test_each_brief_redaction_is_as_stated",
    "the oracle identity binds the oracle file, with ruling KEEP":
        "test_the_oracle_identity_binds_the_oracle_file_with_keep",
    REGISTRY_MESSAGE: "test_the_registry_is_the_base_with_exactly_the_five_ruled_entries",
    "the evolution surface record derives 31 exact or prefix gate entries":
        "test_the_gate_list_is_31_exact_or_prefix_entries",
    RIDER: "test_the_registry_rider_and_its_one_gate_path",
    "one recorded sha256 per path: ": "test_one_recorded_sha256_per_path",
    "the recorded paths 259 changed are exactly the three living catalogs":
        "test_the_recorded_paths_259_changed_are_the_living_catalogs",
    "a living catalog is rebuilt to its base bytes: ": "test_the_living_catalogs_are_rebuilt_to_their_base_bytes",
    "every recorded path is read once": "test_the_base_reads_are_bound_by_the_record",
    "the recorded base bytes are bound: ": "test_the_base_reads_are_bound_by_the_record",
    "the reference model returns no refusal for the adopted record":
        "test_the_model_returns_no_refusal_and_each_scope_mutant_is_refused",
    "unreviewed current source: ": "test_the_canonical_check_reads_this_eras_bytes",
    "canonical byte-minimal inverse hunks: ": "test_whole_line_hunks_are_refused_where_canonical_ones_differ"}
NAMED_MESSAGES = {FREEZE: "FREEZE", REGISTRY_MESSAGE: "REGISTRY_MESSAGE", RIDER: "RIDER"}


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
