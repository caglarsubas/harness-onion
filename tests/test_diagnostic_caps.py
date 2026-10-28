"""Exact source lineage for MET-PERF-041; the pytest-diagnostics caps under the 32 MiB output ceiling: the three constants and the derived scan limits against the limits record, nothing else in the module changed by canonical hunk, the live pin moving alone, the ceiling and its 2 MiB reserve, the historical records byte-identical, the recorded outcomes against the boundary table, and the executed checks at full size (once, in the chain test) and at small scale, checked in the validator."""
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

from scripts import validate_diagnostic_caps as profile
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
    # The newer MET-ENFORCE-039 layer is projected away before this layer's payload checks.
    return profile.successor.historical_catalog(packets())


def changed_test():
    return next(path for path in profile._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert profile.validate() is None
    current = packets()
    accepted = profile.historical_catalog(current)
    assert len(current) == 269 and len(accepted) == 252
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
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET}
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


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "np5_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = profile.historical_bytes(path, raw) if route in ("current_test", "old_bytes") else None
    current_packets = packets() if route == "catalog" else None
    layer = layer_packets() if route == "payloads" else None
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
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
    with pytest.raises(ValueError, match="diagnostic caps history authority digest"):
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
    assert len(profile.historical_catalog(current)) == 252


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
    assert len(profile.historical_catalog(current)) == 252
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
    assert len(rules) == 253 and len(parsed) == 252
    assert profile._packet_rules() is rules and len(parsed) == 252
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
    with pytest.raises(ValueError, match="diagnostic caps history authority digest"):
        profile.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = layer_packets()
    profile.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "diagnostic-caps-authority.json").write_bytes(
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
    # The newer MET-ENFORCE-039 layer refuses a mutated validator before this layer.
    with pytest.raises(ValueError, match="unreviewed current source: scripts/validate_diagnostic_caps.py"):
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
            assert all("validate_" not in alias.name or alias.name == "validate_i06_backend_profile_v4"
                       for alias in node.names)


def _count_authority_reads(monkeypatch):
    counts = {}
    for module in (profile.successor, profile, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner):
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
    expected = {module.__name__: 1 for module in (profile.successor, profile, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner)}
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


def _replace(raw, old, new):
    assert raw.count(old) >= 1, old
    return raw.replace(old, new, 1)


def _limits_with(monkeypatch, change):
    """A changed restatement (a copy of LIMITS), for the checks that read it directly."""
    limits = deepcopy(profile.LIMITS)
    change(limits)
    monkeypatch.setattr(profile, "LIMITS", limits)


def _rebind_limits(monkeypatch, mutate):
    value = json.loads(profile.reviewed_bytes(profile.LIMITS_RECORD))
    mutate(value)
    _rebind(monkeypatch, {profile.LIMITS_RECORD: (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")})


def _era_raws():
    raw = profile.reviewed_bytes(profile.DIAGNOSTICS)
    return raw, profile._undo_this_layer(profile.DIAGNOSTICS, raw)


def _repair():
    repair = profile.reviewed_bytes(profile.REPAIR_TEST)
    return repair, profile._undo_this_layer(profile.REPAIR_TEST, repair)


VALIDATE = profile.validate_diagnostic_caps
# The full-size executed checks run once per session, inside test_exact_current_source_and_complete_history_chain's
# profile.validate(); every other test here runs them at small scale or replaces them, so the file stays cheap.
NEW_SHA = profile.ERA_SHA256[profile.DIAGNOSTICS]


def test_the_caps_hold_for_this_era_with_the_full_size_checks_called_once(monkeypatch):
    calls = []
    monkeypatch.setattr(profile, "executed_checks", lambda modules: calls.append(modules))
    assert VALIDATE() is None
    assert len(calls) == 1
    new, base = calls[0].new, calls[0].base
    assert (new.MAX_PROCESS_BYTES, new.MAX_EVENTS, new.MAX_SCAN_LINES, new.MAX_SCAN_BYTES) == (31457280, 140000, 154000, 32505856)
    assert (base.MAX_PROCESS_BYTES, base.MAX_EVENTS, base.MAX_SCAN_LINES, base.MAX_SCAN_BYTES) == (20971520, 100000, 110000,
                                                                                                    22020096)


def test_every_era_file_is_pinned_and_read_through_reviewed_bytes():
    assert set(profile.ERA_SHA256) == {
        "ci/pytest_diagnostics.py", "tests/test_diagnostic_repair.py", "tests/test_pytest_diagnostics.py",
        "architecture/diagnostic-caps/README.md", "architecture/diagnostic-caps/limits.json",
        "task-packets/MET-PERF-028.yaml", "architecture/packet-schema-performance-authority.json",
        "architecture/load-deadlines-authority.json", "architecture/load-deadlines/limits.json",
        "architecture/load-deadlines/README.md", "scripts/validate_load_deadlines.py"}
    assert set(profile.NEW_FILES) | set(profile.HISTORICAL_RECORDS) <= set(profile.ERA_SHA256)
    for path, expected in profile.ERA_SHA256.items():
        assert profile.digest(profile.reviewed_bytes(path)) == expected


@pytest.mark.parametrize("path", sorted(profile.ERA_SHA256))
def test_every_era_file_is_bound_by_digest_before_anything_runs(monkeypatch, path):
    original = profile.reviewed_bytes
    executed = []
    monkeypatch.setattr(profile, "reviewed_bytes", lambda target: original(target) + b" " if target == path else original(target))
    for name in ("validate_contract_files", "era_inputs", "executed_checks"):
        monkeypatch.setattr(profile, name, lambda *args, _name=name: executed.append(_name))
    with pytest.raises(ValueError, match=re.escape("unreviewed DIAGNOSTIC-CAPS source: " + path)):
        VALIDATE()
    assert executed == []


def test_a_path_outside_the_era_is_refused_before_it_is_read(monkeypatch):
    read = []
    monkeypatch.setattr(profile, "reviewed_bytes", lambda target: read.append(target))
    with pytest.raises(ValueError, match="MET-PERF-041 reviewed bytes are bound: architecture/absent.json"):
        profile._verified("architecture/absent.json")
    assert read == []


@pytest.mark.parametrize("name", ["BASE_DIAGNOSTICS_SHA256", "BASE_REPAIR_SHA256"])
def test_the_base_bytes_come_through_this_layers_own_inverse(monkeypatch, name):
    era = profile.era_inputs()
    assert profile.digest(era.base_raw) == "67416db359a8d5953b469e33b92f0b29f3377fdd6daff7fe1a2958e8bc503a23"
    assert profile.digest(era.base_repair) == "7b666bb8bab73ea37037292a53e8f7029f1a9128e0d6379dd75533f2b5e558a2"
    monkeypatch.setattr(profile, name, "0" * 64)
    with pytest.raises(ValueError, match="this layer's reverse hunks project the module back to 67416db3 and the repair "
                                         "test back to 7b666bb8"):
        profile.era_inputs()


# The contract's files ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("change", ["dropped", "duplicate", "changed"])
def test_the_contract_files_are_new_in_this_packet_each_once(monkeypatch, change):
    if change == "dropped":
        record = profile.authority()
        reduced = dict(record, newFiles={k: v for k, v in record["newFiles"].items() if k != profile.CAPS_README})
        monkeypatch.setattr(profile, "authority", lambda: reduced)
    elif change == "duplicate":
        monkeypatch.setattr(profile, "NEW_FILES", profile.NEW_FILES + (profile.CAPS_README,))
    else:
        rules = dict(profile._PROJECTION_RULES)
        rules[profile.LIMITS_RECORD] = rules[profile.DIAGNOSTICS]
        monkeypatch.setattr(profile, "_PROJECTION_RULES", MappingProxyType(rules))
    with pytest.raises(ValueError, match="the contract's files are new in this packet, each once"):
        profile.validate_contract_files()


def test_the_contract_directory_must_not_be_a_link(monkeypatch):
    original = profile.reviewed_mode
    monkeypatch.setattr(profile, "reviewed_mode",
                        lambda path: stat.S_IFLNK | 0o777 if path == profile.CAPS_DIR[:-1] else original(path))
    with pytest.raises(ValueError, match="the contract directory is a directory, not a link"):
        profile.validate_contract_files()


@pytest.mark.parametrize("change,message", [
    ("extra", "the contract directory holds exactly its files"),
    ("executable", "a contract file is a regular file of git mode 100644: "),
    ("link", "a contract file is a regular file of git mode 100644: "),
])
def test_the_contract_tree_is_closed_and_every_file_is_mode_100644(monkeypatch, change, message):
    assert profile.validate_contract_files() is None
    if change == "extra":
        tree = profile.reviewed_tree(profile.CAPS_DIR)
        monkeypatch.setattr(profile, "reviewed_tree", lambda directory: {**tree, profile.CAPS_DIR + "later.json": 0o100644})
    else:
        original = profile.reviewed_mode
        mode = 0o100755 if change == "executable" else stat.S_IFLNK | 0o777
        monkeypatch.setattr(profile, "reviewed_mode", lambda path: mode if path == profile.LIMITS_RECORD else original(path))
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.validate_contract_files()


@pytest.mark.parametrize("path", ["architecture/diagnostic-caps/README.md", "architecture/diagnostic-caps/limits.json"])
@pytest.mark.parametrize("marker", [b"/" + b"Users/x/notes", b"/" + b"private/tmp/x", b"~/." + b"local/state/x"])
def test_no_added_file_may_carry_an_absolute_local_path(monkeypatch, path, marker):
    _rebind(monkeypatch, {path: profile.reviewed_bytes(path) + marker + b"\n"})
    with pytest.raises(ValueError, match=re.escape("no absolute local path in a file this packet adds: " + path)):
        profile.validate_contract_files()


# The limits record ------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("mutate", [
    lambda value: value["caps"][1].__setitem__("after", 140001),
    lambda value: value["caps"][0].__setitem__("after", 31457280.0),
    lambda value: value["ceiling"].__setitem__("reserveBytes", 2097153),
    lambda value: value["executedChecks"]["W"]["lastPass"].__setitem__("bytes", 31455197),
    lambda value: value["boundaries"].pop(),
    lambda value: value["measuredCost"].__setitem__("wallSeconds", 1.0),
    lambda value: value.__setitem__("extra", True),
    lambda value: value.pop("evidenceClass"),
])
def test_the_limits_record_equals_its_restatement_type_strictly(monkeypatch, mutate):
    assert profile.validate_limits_record() is None
    _rebind_limits(monkeypatch, mutate)
    with pytest.raises(ValueError, match="closed diagnostic-caps limits record, equal to its restatement"):
        profile.validate_limits_record()


@pytest.mark.parametrize("mutate", [
    lambda value: value["ownerDecisions"].pop(),
    lambda value: value["ownerDecisions"].reverse(),
    lambda value: value["ownerDecisions"][0].__setitem__("date", "2026-10-19"),
    lambda value: value["ownerDecisions"][1].__setitem__("selected", "B"),
    lambda value: value["ownerDecisions"][1]["relayed"].__setitem__(
        1, value["ownerDecisions"][1]["relayed"][1].replace("30 MiB", "32 MiB")),
    lambda value: value["ownerDecisions"][0].__setitem__("note", "extra"),
])
def test_the_owner_decisions_are_recorded_verbatim_and_dated(monkeypatch, mutate):
    _rebind_limits(monkeypatch, mutate)
    with pytest.raises(ValueError, match="owner decisions Q-253-DIAG and Q-DIAGCAP-SIZE recorded verbatim and dated"):
        profile.validate_limits_record()


def test_the_owner_decisions_quote_the_selected_options():
    rows = {row["id"]: row for row in profile.OWNER_DECISIONS}
    assert rows["Q-253-DIAG"]["decision"] == "(a) ci/ cap packet first (Recommended)"
    assert rows["Q-DIAGCAP-SIZE"]["decision"] == "(A) Stay under 32 MiB (Recommended)"
    assert all(row["date"] == "2026-10-20" and row["decision"] in row["relayed"][0] for row in rows.values())


@pytest.mark.parametrize("change", ["duration", "phases", "clock"])
def test_the_restated_profiles_are_the_executed_profiles(monkeypatch, change):
    if change == "clock":
        monkeypatch.setattr(profile, "CLOCK", MappingProxyType(dict(profile.CLOCK, laterCallBaseSeconds=1000.0)))
    else:
        profiles = dict(profile.PROFILES)
        edit = {"durationSeconds": 0.09999} if change == "duration" else {"phases": ("setup", "call", "teardown")}
        profiles["W"] = MappingProxyType(dict(profiles["W"], **edit))
        monkeypatch.setattr(profile, "PROFILES", MappingProxyType(profiles))
    with pytest.raises(ValueError, match="the restated profiles are the executed profiles"):
        profile.validate_limits_record()


# The caps, the live pin and the ceiling ---------------------------------------------------------------------------------

@pytest.mark.parametrize("target,old,new,message", [
    ("era", b"MAX_EVENTS = 140_000\n", b"MAX_EVENTS = 140_001\n",
     "the three caps and the derived scan limits are limits.json's after values"),
    ("era", b"MAX_PROCESS_BYTES = 30 * 1024 * 1024\n", b"MAX_PROCESS_BYTES = 31 * 1024 * 1024\n",
     "the three caps and the derived scan limits are limits.json's after values"),
    ("base", b"MAX_EVENTS = 100_000\n", b"MAX_EVENTS = 100_001\n", "the base module's caps are limits.json's before values"),
    ("era", b"MAX_SCAN_LINES = MAX_EVENTS + MAX_EVENTS // 10\n", b"MAX_SCAN_LINES = 154_000\n",
     "MAX_SCAN_LINES is derived in code as MAX_EVENTS + MAX_EVENTS // 10"),
    ("era", b"MAX_SCAN_BYTES = MAX_PROCESS_BYTES + 1024 * 1024\n", b"MAX_SCAN_BYTES = 32_505_856\n",
     "MAX_SCAN_LINES is derived in code as MAX_EVENTS + MAX_EVENTS // 10"),
    ("era", b"MAX_RECORD_BYTES = 1024\n", b"MAX_RECORD_BYTES = 2048\n", "the record, node and failure limits are 27c5460's"),
    ("era", b"MAX_FAILURES = 16\n", b"MAX_FAILURES = 32\n", "the record, node and failure limits are 27c5460's"),
    ("era", b'PREFIX = b"PYTEST_DIAGNOSTIC="\n', b'PREFIX = b"PYTEST_DIAGNOSTIC="  # changed\n',
     "nothing else in ci/pytest_diagnostics.py differs from 27c5460, by canonical hunk"),
])
def test_each_cap_is_checked_exactly(target, old, new, message):
    raw, base = _era_raws()
    assert profile.validate_caps(raw, base).new.MAX_EVENTS == 140000
    if target == "era":
        raw = _replace(raw, old, new)
    else:
        base = _replace(base, old, new)
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.validate_caps(raw, base)


def test_the_recorded_caps_drive_the_check(monkeypatch):
    _limits_with(monkeypatch, lambda value: value["unchanged"][0].__setitem__("value", 2048))
    with pytest.raises(ValueError, match="the record, node and failure limits are 27c5460's"):
        profile.validate_caps(*_era_raws())


@pytest.mark.parametrize("change,message", [
    (lambda raw: raw.replace(NEW_SHA.encode(), b"67416db359a8d5953b469e33b92f0b29f3377fdd6daff7fe1a2958e8bc503a23"),
     "tests/test_diagnostic_repair.py's live pin (line 133) is the new module's digest"),
    (lambda raw: raw.replace(b"3c0afe5686f0c39cea2f68d97f50549d0faba890539c3e20aae1d88b2305139f",
                             b"58cabbee54b0dbfe3ca3ce28e3b60a844ad77fe410f39404f0321b6be4ab5e28"),
     "line 132's pin of the predecessor diagnostics test is unchanged"),
    (lambda raw: raw + b"# changed\n", "the repair test's reverse hunk spans line 133's bytes only"),
])
def test_the_live_pin_moves_alone(change, message):
    repair, base = _repair()
    assert profile.validate_live_pin(repair, base, NEW_SHA) is None
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.validate_live_pin(change(repair), base, NEW_SHA)


def test_the_live_pin_hunk_must_be_the_restated_one(monkeypatch):
    repair, base = _repair()
    at, removed, inserted = profile.REPAIR_HUNKS[0]
    monkeypatch.setattr(profile, "REPAIR_HUNKS", ((at - 1, b" " + removed, b" " + inserted),))
    with pytest.raises(ValueError, match="the repair test's reverse hunk spans line 133's bytes only"):
        profile.validate_live_pin(repair, base, NEW_SHA)


@pytest.mark.parametrize("change,message", [
    (lambda value: value["ceiling"].__setitem__("reserveBytes", 2097153),
     "the 32 MiB ceiling, the 2 MiB reserve and the stream cap are restated"),
    (lambda value: value["ceiling"].__setitem__("changed", True),
     "the 32 MiB ceiling, the 2 MiB reserve and the stream cap are restated"),
    (lambda value: (value["caps"][0].__setitem__("after", 31457281), value["ceiling"].__setitem__("streamCapBytes", 31457281)),
     "MAX_PROCESS_BYTES and the 2 MiB reserve fit the 32 MiB ceiling"),
    (lambda value: value["ceiling"]["otherOutputBytes"].__setitem__("totalAbout", 89000),
     "the reserve covers the other output, and the whole run at W's boundary stays under the ceiling"),
    (lambda value: value["ceiling"].__setitem__("wholeRunAtWBoundaryAboutBytes", 31544000),
     "the reserve covers the other output, and the whole run at W's boundary stays under the ceiling"),
])
def test_the_ceiling_and_the_reserve_are_checked(monkeypatch, change, message):
    assert profile.validate_ceiling() is None
    _limits_with(monkeypatch, change)
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.validate_ceiling()


def test_the_ceiling_constants_are_restated_not_derived(monkeypatch):
    assert profile.OUTPUT_CEILING_BYTES == 33554432 and profile.RESERVE_BYTES == 2097152
    monkeypatch.setattr(profile, "RESERVE_BYTES", 2 * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match="the 32 MiB ceiling, the 2 MiB reserve and the stream cap are restated"):
        profile.validate_ceiling()


# The historical records -------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("path,old,new,message", [
    ("task-packets/MET-PERF-028.yaml", b"Existing32MiB outer ceiling stays unchanged",
     b"Existing 32MiB outer ceiling stays unchanged", "MET-PERF-028.yaml's five sentences stay byte-exact, once each"),
    ("task-packets/MET-PERF-028.yaml", b"are20MiB/process", b"are30MiB/process",
     "MET-PERF-028.yaml's five sentences stay byte-exact, once each"),
    ("architecture/packet-schema-performance-authority.json",
     b"67416db359a8d5953b469e33b92f0b29f3377fdd6daff7fe1a2958e8bc503a23",
     b"ac9e70395413356f6348180c0c61a7adec57999f770feed59967b6eac7167745",
     "MET-PERF-028's authority pins the base module, its repair test and its own tests"),
    ("architecture/load-deadlines-authority.json", b"7b666bb8bab73ea37037292a53e8f7029f1a9128e0d6379dd75533f2b5e558a2",
     b"68fca6b738e11fff0afb371c7e6dc7893ed315dcaabe34fbb148e4f1d22b8c7d",
     "MET-PERF-038's authority pins the repair test before and after its own change"),
    ("scripts/validate_load_deadlines.py", b'    "tests/test_diagnostic_repair.py": "7b666bb8',
     b'    "tests/test_diagnostic_repair.py": "7b666bb9', "MET-PERF-038's validator still pins the repair test at 7b666bb8"),
])
def test_each_historical_pin_is_checked(monkeypatch, path, old, new, message):
    assert profile.validate_historical_records() is None
    _rebind(monkeypatch, {path: _replace(profile.reviewed_bytes(path), old, new)})
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.validate_historical_records()


@pytest.mark.parametrize("path,key", [("ci/pytest_diagnostics.py", "beforeSha256"), ("tests/test_diagnostic_repair.py",
                                                                                     "beforeSha256"),
                                      ("ci/pytest_diagnostics.py", "afterSha256")])
def test_this_packets_reverse_routes_reach_the_historical_pins(monkeypatch, path, key):
    rules = dict(profile._PROJECTION_RULES)
    rules[path] = MappingProxyType(dict(rules[path], **{key: "0" * 64}))
    monkeypatch.setattr(profile, "_PROJECTION_RULES", MappingProxyType(rules))
    with pytest.raises(ValueError, match="this packet's authority carries the reverse routes to 67416db3 and 7b666bb8"):
        profile.validate_historical_records()


@pytest.mark.parametrize("change", ["digest", "changed"])
def test_every_historical_record_is_byte_identical(monkeypatch, change):
    if change == "digest":
        _limits_with(monkeypatch, lambda value: value["historicalLimitRecords"][1].__setitem__("sha256", "0" * 64))
    else:
        # A route for MET-PERF-021's own tests: the other pins stay in place; only the byte-identity check sees it.
        rules = dict(profile._PROJECTION_RULES)
        rules["tests/test_pytest_diagnostics.py"] = rules["ci/pytest_diagnostics.py"]
        monkeypatch.setattr(profile, "_PROJECTION_RULES", MappingProxyType(rules))
    with pytest.raises(ValueError, match="every historical record is byte-identical at its recorded digest"):
        profile.validate_historical_records()


# The recorded executed outcomes -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("change,message", [
    (lambda value: value["executedChecks"]["W"]["lastPass"].__setitem__("tests", 22873),
     "the executed boundary is the boundary table's: W"),
    (lambda value: value["executedChecks"]["S"]["firstFail"].__setitem__("tests", 23335),
     "the executed boundary is the boundary table's: S"),
    (lambda value: value["executedChecks"]["W"]["lastPass"].__setitem__("dropped", 1),
     "the last passing count completes with every record written, within the byte cap: W"),
    (lambda value: value["executedChecks"]["S"]["lastPass"].__setitem__("events", 139998),
     "the last passing count completes with every record written, within the byte cap: S"),
    (lambda value: value["executedChecks"]["W"]["firstFail"].__setitem__("reasons", ["EVENT_LIMIT"]),
     "one test later fails closed with its reason and exit 1, within the byte cap: W"),
    (lambda value: value["executedChecks"]["S"]["firstFail"].__setitem__("exitCode", 0),
     "one test later fails closed with its reason and exit 1, within the byte cap: S"),
    (lambda value: value["executedChecks"]["incident"]["outcome"].__setitem__("tests", 16305),
     "the incident run is the measurement's, failing first where the base R boundary says"),
    (lambda value: value["executedChecks"]["incident"]["outcome"].__setitem__("firstIncompleteTest", 15461),
     "the incident run is the measurement's, failing first where the base R boundary says"),
    (lambda value: value["executedChecks"]["scan"]["exact"].__setitem__("status", "INCOMPLETE"),
     "the scan records are COMPLETE at exactly the scan limits, INPUT_LIMIT one byte past and SCAN_LIMIT one line past"),
    (lambda value: value["executedChecks"]["scan"]["oneLinePast"].__setitem__("incompleteReasons", []),
     "the scan records are COMPLETE at exactly the scan limits, INPUT_LIMIT one byte past and SCAN_LIMIT one line past"),
    (lambda value: value["headroom"].__setitem__("testsOverMeasured", 6567),
     "the headroom follows from the boundary table and the measurement"),
    (lambda value: value["headroom"]["packets"][0].__setitem__("packets", 10),
     "the headroom follows from the boundary table and the measurement"),
])
def test_the_recorded_outcomes_say_what_section_8_says(monkeypatch, change, message):
    assert profile.validate_executed_records() is None
    _limits_with(monkeypatch, change)
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.validate_executed_records()


# The executed checks at small scale (the same code; the caps rewritten in this era's bytes) -----------------------------

SMALL_NEW = ((b"MAX_PROCESS_BYTES = 30 * 1024 * 1024\n", b"MAX_PROCESS_BYTES = 120 * 1024\n"),
             (b"MAX_EVENTS = 140_000\n", b"MAX_EVENTS = 600\n"))
SMALL_BASE = ((b"MAX_PROCESS_BYTES = 20 * 1024 * 1024\n", b"MAX_PROCESS_BYTES = 80 * 1024\n"),
              (b"MAX_EVENTS = 100_000\n", b"MAX_EVENTS = 400\n"))
SMALL_INCIDENT_TESTS = 70


def _edit(raw, pairs):
    for old, new in pairs:
        assert raw.count(old) == 1, old
        raw = raw.replace(old, new)
    return raw


def _small_module(edits=(), name="_met_perf_041_small"):
    raw, _base = _era_raws()
    return profile.diagnostics_module(_edit(raw, SMALL_NEW + tuple(edits)), name)


def _small_base():
    _raw, base = _era_raws()
    return profile.diagnostics_module(_edit(base, SMALL_BASE), "_met_perf_041_small_base")


def _last_passing(module, name):
    tests = 0
    while profile.run_profile(module, name, tests + 1)["exitCode"] == 0:
        tests += 1
    return tests


def _small_scale(monkeypatch):
    """The executed checks' recorded outcomes re-derived at small scale (120 KiB / 600 events; the base 80 KiB / 400
    events), where W is bound by bytes and S by events, as at full size; LIMITS carries them for the check."""
    new, base = _small_module(), _small_base()
    checks = {}
    for name, reason in (("W", "OUTPUT_LIMIT"), ("S", "EVENT_LIMIT")):
        last = _last_passing(new, name)
        checks[name] = {"module": "candidate", "profile": name, "reason": reason,
                        "lastPass": profile.run_profile(new, name, last),
                        "firstFail": profile.run_profile(new, name, last + 1)}
        assert checks[name]["firstFail"]["reasons"] == [reason]
    collected = bytearray()
    profile.run_profile(new, "W", checks["W"]["lastPass"]["tests"], collected)
    streams = profile.scan_streams(new, bytes(collected))
    checks["scan"] = {"stream": "small", **{case: profile.scan_summary(new, next(streams))
                                            for case in ("exact", "oneBytePast", "oneLinePast")}}
    checks["incident"] = {"module": "base", "profile": "R",
                          "outcome": profile.run_profile(base, "R", SMALL_INCIDENT_TESTS)}
    assert checks["incident"]["outcome"]["reasons"] == ["OUTPUT_LIMIT"]
    _limits_with(monkeypatch, lambda value: value.__setitem__("executedChecks", checks))
    return types.SimpleNamespace(new=new, base=base)


def test_the_executed_checks_hold_at_small_scale(monkeypatch):
    modules = _small_scale(monkeypatch)
    assert profile.executed_checks(modules) is None
    checks = profile.LIMITS["executedChecks"]
    assert checks["scan"]["exact"]["status"] == "COMPLETE" and checks["scan"]["exact"]["inputBytes"] == modules.new.MAX_SCAN_BYTES
    assert checks["scan"]["oneBytePast"]["incompleteReasons"] == ["INPUT_LIMIT"]
    assert checks["scan"]["oneLinePast"]["incompleteReasons"] == ["SCAN_LIMIT"]


@pytest.mark.parametrize("edits,base_is_new,message", [
    (((b"MAX_PROCESS_BYTES = 120 * 1024\n", b"MAX_PROCESS_BYTES = 116 * 1024\n"),), False,
     "profile W completes at its last passing count"),
    (((b"MAX_PROCESS_BYTES = 120 * 1024\n", b"MAX_PROCESS_BYTES = 124 * 1024\n"),), False,
     "profile W fails closed with OUTPUT_LIMIT and exit 1 one test later"),
    (((b"MAX_EVENTS = 600\n", b"MAX_EVENTS = 594\n"),), False, "profile S completes at its last passing count"),
    (((b"MAX_EVENTS = 600\n", b"MAX_EVENTS = 606\n"),), False, "profile S fails closed with EVENT_LIMIT one test later"),
    (((b"    if len(raw) > MAX_SCAN_BYTES:\n", b"    if len(raw) >= MAX_SCAN_BYTES:\n"),), False,
     "summarize_nested reports COMPLETE on a stream of exactly MAX_SCAN_BYTES and MAX_SCAN_LINES"),
    (((b"    if len(raw) > MAX_SCAN_BYTES:\n", b"    if len(raw) > MAX_SCAN_BYTES + 1:\n"),), False,
     "summarize_nested reports INPUT_LIMIT one byte past MAX_SCAN_BYTES"),
    (((b"    while cursor < len(raw) and lines < MAX_SCAN_LINES:\n",
       b"    while cursor < len(raw) and lines <= MAX_SCAN_LINES:\n"),), False,
     "summarize_nested reports SCAN_LIMIT one line past MAX_SCAN_LINES"),
    ((), True, "the base module fails profile R at the incident's 16,306 tests with OUTPUT_LIMIT"),
])
def test_each_executed_check_fails_when_its_outcome_changes(monkeypatch, edits, base_is_new, message):
    modules = _small_scale(monkeypatch)
    new = _small_module(edits, "_met_perf_041_small_mutant") if edits else modules.new
    mutant = types.SimpleNamespace(new=new, base=new if base_is_new else modules.base)
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.executed_checks(mutant)


def test_the_scan_streams_need_room_for_their_padding():
    new = _small_module()
    with pytest.raises(ValueError, match="the producer stream leaves room for at least two padding lines"):
        next(profile.scan_streams(new, b"x\n" * (new.MAX_SCAN_LINES - 1)))


def test_the_executed_checks_read_no_file(monkeypatch):
    modules = _small_scale(monkeypatch)

    def refused(*args, **kwargs):
        raise AssertionError("file read: %r" % (args[:1],))
    monkeypatch.setattr(Path, "read_bytes", refused)
    monkeypatch.setattr(Path, "read_text", refused)
    monkeypatch.setattr(Path, "open", refused)
    import builtins
    monkeypatch.setattr(builtins, "open", refused)
    assert profile.executed_checks(modules) is None


# Reads, projection and the canonical hunks ------------------------------------------------------------------------------

SEMANTIC_FUNCTIONS = {"_verified", "_json", "_holds", "_bound", "diagnostics_module", "run_profile", "scan_streams",
                      "scan_summary", "era_inputs", "validate_contract_files", "validate_limits_record", "validate_caps",
                      "validate_live_pin", "validate_ceiling", "validate_historical_records", "validate_executed_records",
                      "executed_checks", "validate_diagnostic_caps"}


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


def test_the_check_reads_no_unverified_byte(monkeypatch):
    """Every byte the static check uses comes through reviewed_bytes: with those served from memory, the authority the
    generic layer checked served as checked, the executed checks replaced (they read no file; see the test above) and
    every other file read refused, the whole check still holds."""
    paths = set(profile.ERA_SHA256) | set(profile._PROJECTION_RULES)
    served = {path: profile.reviewed_bytes(path) for path in paths}
    record = profile.authority()
    monkeypatch.setattr(profile, "reviewed_bytes", lambda target: served[target])
    monkeypatch.setattr(profile, "authority", lambda: record)
    monkeypatch.setattr(profile, "executed_checks", lambda modules: None)

    def refused(*args, **kwargs):
        raise AssertionError("unverified read: %r" % (args[:1],))
    monkeypatch.setattr(Path, "read_bytes", refused)
    monkeypatch.setattr(Path, "read_text", refused)
    monkeypatch.setattr(Path, "open", refused)
    import builtins
    monkeypatch.setattr(builtins, "open", refused)
    assert VALIDATE() is None


def test_a_later_successor_leaves_this_era_valid_through_projection(monkeypatch):
    monkeypatch.setattr(profile, "executed_checks", lambda modules: None)
    original, reviewed = profile.regular_bytes, profile.reviewed_bytes
    era = {path: reviewed(path) for path in (profile.DIAGNOSTICS, profile.REPAIR_TEST)}
    later = {profile.DIAGNOSTICS: era[profile.DIAGNOSTICS].replace(b"MAX_EVENTS = 140_000\n", b"MAX_EVENTS = 150_000\n", 1),
             profile.REPAIR_TEST: era[profile.REPAIR_TEST] + b"\n"}
    monkeypatch.setattr(profile, "regular_bytes", lambda path: later.get(path) or original(path))
    with pytest.raises(ValueError):
        VALIDATE()
    monkeypatch.setattr(profile, "reviewed_bytes", lambda path: era[path] if path in later else reviewed(path))
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
    path = profile.DIAGNOSTICS
    after = profile.reviewed_bytes(path)
    before = profile._undo_this_layer(path, after)
    line = _line_hunks(after, before)
    assert line != rules[path]["reverseHunks"] and profile._inverse(after, line) == before
    rules[path] = MappingProxyType(dict(rules[path], reverseHunks=line))
    monkeypatch.setattr(profile, "_PROJECTION_RULES", MappingProxyType(rules))
    with pytest.raises(ValueError, match=re.escape("canonical byte-minimal inverse hunks: " + path)):
        profile.validate_canonical_hunks()


def test_the_canonical_check_reads_this_eras_bytes(monkeypatch):
    path = next(iter(profile._PROJECTION_RULES))
    original = profile.reviewed_bytes
    monkeypatch.setattr(profile, "reviewed_bytes", lambda target: original(target) + b" " if target == path else original(target))
    with pytest.raises(ValueError, match=re.escape("unreviewed current source: " + path)):
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
    assert profile._PROJECTION_RULES[profile.DIAGNOSTICS]["reverseHunks"] == profile.DIAGNOSTICS_HUNKS
    assert profile._PROJECTION_RULES[profile.REPAIR_TEST]["reverseHunks"] == profile.REPAIR_HUNKS


# Every check can fail (252's packet review lesson P1-1: no check without a failing test) ------------------------------

CHECK_TESTS = {
    "MET-PERF-041 reviewed bytes are bound: ": "test_a_path_outside_the_era_is_refused_before_it_is_read",
    "unreviewed DIAGNOSTIC-CAPS source: ": "test_every_era_file_is_bound_by_digest_before_anything_runs",
    "the producer stream leaves room for at least two padding lines of at least three bytes":
        "test_the_scan_streams_need_room_for_their_padding",
    "this layer's reverse hunks project the module back to 67416db3 and the repair test back to 7b666bb8":
        "test_the_base_bytes_come_through_this_layers_own_inverse",
    "the contract's files are new in this packet, each once": "test_the_contract_files_are_new_in_this_packet_each_once",
    "the contract directory is a directory, not a link": "test_the_contract_directory_must_not_be_a_link",
    "the contract directory holds exactly its files": "test_the_contract_tree_is_closed_and_every_file_is_mode_100644",
    "a contract file is a regular file of git mode 100644: ":
        "test_the_contract_tree_is_closed_and_every_file_is_mode_100644",
    "no absolute local path in a file this packet adds: ": "test_no_added_file_may_carry_an_absolute_local_path",
    "closed diagnostic-caps limits record, equal to its restatement":
        "test_the_limits_record_equals_its_restatement_type_strictly",
    "owner decisions Q-253-DIAG and Q-DIAGCAP-SIZE recorded verbatim and dated":
        "test_the_owner_decisions_are_recorded_verbatim_and_dated",
    "the restated profiles are the executed profiles": "test_the_restated_profiles_are_the_executed_profiles",
    "the three caps and the derived scan limits are limits.json's after values": "test_each_cap_is_checked_exactly",
    "the base module's caps are limits.json's before values": "test_each_cap_is_checked_exactly",
    "MAX_SCAN_LINES is derived in code as MAX_EVENTS + MAX_EVENTS // 10 and MAX_SCAN_BYTES as MAX_PROCESS_BYTES + 1 MiB":
        "test_each_cap_is_checked_exactly",
    "the record, node and failure limits are 27c5460's": "test_each_cap_is_checked_exactly",
    "nothing else in ci/pytest_diagnostics.py differs from 27c5460, by canonical hunk": "test_each_cap_is_checked_exactly",
    "tests/test_diagnostic_repair.py's live pin (line 133) is the new module's digest": "test_the_live_pin_moves_alone",
    "line 132's pin of the predecessor diagnostics test is unchanged": "test_the_live_pin_moves_alone",
    "the repair test's reverse hunk spans line 133's bytes only": "test_the_live_pin_moves_alone",
    "the 32 MiB ceiling, the 2 MiB reserve and the stream cap are restated": "test_the_ceiling_and_the_reserve_are_checked",
    "MAX_PROCESS_BYTES and the 2 MiB reserve fit the 32 MiB ceiling": "test_the_ceiling_and_the_reserve_are_checked",
    "the reserve covers the other output, and the whole run at W's boundary stays under the ceiling":
        "test_the_ceiling_and_the_reserve_are_checked",
    "MET-PERF-028.yaml's five sentences stay byte-exact, once each": "test_each_historical_pin_is_checked",
    "MET-PERF-028's authority pins the base module, its repair test and its own tests": "test_each_historical_pin_is_checked",
    "MET-PERF-038's authority pins the repair test before and after its own change": "test_each_historical_pin_is_checked",
    "MET-PERF-038's validator still pins the repair test at 7b666bb8": "test_each_historical_pin_is_checked",
    "this packet's authority carries the reverse routes to 67416db3 and 7b666bb8":
        "test_this_packets_reverse_routes_reach_the_historical_pins",
    "every historical record is byte-identical at its recorded digest": "test_every_historical_record_is_byte_identical",
    "the executed boundary is the boundary table's: ": "test_the_recorded_outcomes_say_what_section_8_says",
    "the last passing count completes with every record written, within the byte cap: ":
        "test_the_recorded_outcomes_say_what_section_8_says",
    "one test later fails closed with its reason and exit 1, within the byte cap: ":
        "test_the_recorded_outcomes_say_what_section_8_says",
    "the incident run is the measurement's, failing first where the base R boundary says":
        "test_the_recorded_outcomes_say_what_section_8_says",
    "the scan records are COMPLETE at exactly the scan limits, INPUT_LIMIT one byte past and SCAN_LIMIT one line past":
        "test_the_recorded_outcomes_say_what_section_8_says",
    "the headroom follows from the boundary table and the measurement": "test_the_recorded_outcomes_say_what_section_8_says",
    "profile W completes at its last passing count": "test_each_executed_check_fails_when_its_outcome_changes",
    "profile W fails closed with OUTPUT_LIMIT and exit 1 one test later":
        "test_each_executed_check_fails_when_its_outcome_changes",
    "profile S completes at its last passing count": "test_each_executed_check_fails_when_its_outcome_changes",
    "profile S fails closed with EVENT_LIMIT one test later": "test_each_executed_check_fails_when_its_outcome_changes",
    "summarize_nested reports COMPLETE on a stream of exactly MAX_SCAN_BYTES and MAX_SCAN_LINES":
        "test_each_executed_check_fails_when_its_outcome_changes",
    "summarize_nested reports INPUT_LIMIT one byte past MAX_SCAN_BYTES":
        "test_each_executed_check_fails_when_its_outcome_changes",
    "summarize_nested reports SCAN_LIMIT one line past MAX_SCAN_LINES":
        "test_each_executed_check_fails_when_its_outcome_changes",
    "the base module fails profile R at the incident's 16,306 tests with OUTPUT_LIMIT":
        "test_each_executed_check_fails_when_its_outcome_changes",
    "unreviewed current source: ": "test_the_canonical_check_reads_this_eras_bytes",
    "canonical byte-minimal inverse hunks: ": "test_whole_line_hunks_are_refused_where_canonical_ones_differ"}


def _refusal_messages():
    """The constant text of every refusal in the semantic check's functions and the canonical-hunk guard: a require or
    _bound call's message, cut at its first format field."""
    tree = ast.parse(profile.regular_bytes(profile.VALIDATOR_PATH))
    found = set()
    for node in tree.body:
        if not (isinstance(node, ast.FunctionDef) and node.name in SEMANTIC_FUNCTIONS | {"validate_canonical_hunks"}):
            continue
        for call in ast.walk(node):
            if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                    and call.func.id in ("require", "_bound") and len(call.args) == 2):
                continue
            message = call.args[1]
            while isinstance(message, ast.BinOp):
                message = message.left
            if isinstance(message, ast.Name):
                assert message.id == "message" and node.name == "_bound", ast.dump(call)
            else:
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
        assert message in source or message[:40] in source or any(row.startswith(message) for row in _messages_of(name)), \
            message


def _messages_of(name):
    """The expected messages a parametrized test lists in its parametrize marks."""
    rows = []
    for mark in getattr(globals()[name], "pytestmark", []):
        for row in mark.args[1] if len(mark.args) > 1 else []:
            rows += [value for value in (row if isinstance(row, tuple) else (row,)) if isinstance(value, str)]
    return rows
