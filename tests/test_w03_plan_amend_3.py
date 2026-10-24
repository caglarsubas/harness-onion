"""Exact source lineage for MET-ENFORCE-037; W03 obligation-register amendment 3: OBS-HOSTPOL-1 and NP-9 added, HE-003's share in amendment 1's SEC-4 and HI-7 rows corrected as owner decision Q-HE3-3 (a) directs, and HE-004D1's packet scope, applied after amendments 1 and 2, with every rule, citation and the adoption record checked in the validator."""
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

from scripts import validate_w03_plan_amend_3 as profile
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
    # The newer MET-LINUX-007 layer is projected away before this layer's payload checks.
    return profile.successor.historical_catalog(packets())


def changed_test():
    return next(path for path in profile._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert profile.validate() is None
    current = packets()
    accepted = profile.historical_catalog(current)
    assert len(current) == 265 and len(accepted) == 249
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
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET}
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


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "cfp3_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = profile.historical_bytes(path, raw) if route in ("current_test", "old_bytes") else None
    current_packets = packets() if route == "catalog" else None
    layer = layer_packets() if route == "payloads" else None
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
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
    with pytest.raises(ValueError, match="w03 plan amendment 3 history authority digest"):
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
    assert len(profile.historical_catalog(current)) == 249


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
    assert len(profile.historical_catalog(current)) == 249
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
    assert len(rules) == 250 and len(parsed) == 249
    assert profile._packet_rules() is rules and len(parsed) == 249
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
    with pytest.raises(ValueError, match="w03 plan amendment 3 history authority digest"):
        profile.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = layer_packets()
    profile.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "w03-plan-amend-3-authority.json").write_bytes(
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
    # The newer MET-LINUX-007 layer refuses a mutated validator before this layer.
    with pytest.raises(ValueError, match="unreviewed current source: scripts/validate_w03_plan_amend_3.py"):
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
            assert all("validate_" not in alias.name or alias.name == "validate_lab_run_plan"
                       for alias in node.names)


def _count_authority_reads(monkeypatch):
    counts = {}
    for module in (profile.successor, profile, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner):
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
    expected = {module.__name__: 1 for module in (profile.successor, profile, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner)}
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


def _json(path):
    return json.loads(profile.reviewed_bytes(path))


def _status():
    return _json(profile.STATUS_PATH)


def _flip(text, at=-1):
    at = at % len(text)
    return text[:at] + chr(ord(text[at]) ^ 1) + text[at + 1:]


def _rebind_record(monkeypatch, number, change):
    """Serve a changed review record with its status row's record digest re-pinned."""
    path = profile.AM3_DIR + "review-round%d.json" % number
    record = _json(path)
    change(record)
    status = _status()
    status["rounds"][number - 1]["recordSha256"] = profile.digest(_dump(record))
    _rebind(monkeypatch, {path: _dump(record), profile.STATUS_PATH: _dump(status)})


def _rebind_candidate(monkeypatch, number, path, raw):
    """Serve a changed snapshot of candidate number with that candidate's digest re-pinned in the status record."""
    status = _status()
    row = status["candidates"][number - 1]
    row["sha256"][path] = profile.digest(raw)
    _rebind(monkeypatch, {row["snapshot"] + path: raw, profile.STATUS_PATH: _dump(status)})


def _rows(value, obligation):
    return [row for row in value["changes"] if row["obligation"] == obligation]


def _earlier_share(obligation, packet="HE-003"):
    """The share a SHARE_CORRECTED row corrects: amendment 1's PACKETS_ADDED row for obligation."""
    first = _json(profile.AMENDMENT_1)
    return next(row for row in first["changes"]
                if row["obligation"] == obligation and row["change"] == "PACKETS_ADDED")["shares"][packet]


VALIDATE = profile.validate_w03_plan_amend_3
LAST_RECORD = profile.AM3_DIR + "review-round4.json"


def test_the_amendment_holds_for_this_era():
    assert VALIDATE() is None


def test_every_contract_file_and_input_is_pinned():
    pinned = set(profile.ERA_SHA256)
    status = _status()
    assert set(profile.NEW_FILES) | set(profile.FROZEN_PATHS) == pinned and not set(profile.NEW_FILES) & set(profile.FROZEN_PATHS)
    assert set(profile.SUBJECT) | {profile.STATUS_PATH, profile.REVIEW_BRIEF_PATH} <= set(profile.NEW_FILES)
    assert {row["record"] for row in status["rounds"]} <= set(profile.NEW_FILES)
    assert {row["snapshot"] + path for row in status["candidates"] for path in row["keptCopies"]} <= set(profile.NEW_FILES)
    assert {profile.PLAN_V2, profile.AMENDMENT_1, profile.AMENDMENT_2, profile.V5_EDGE, profile.NP4_README} <= set(
        profile.FROZEN_PATHS)
    assert {path for path, _first, _last in profile.citations(_json(profile.AMENDMENT))} <= set(profile.FROZEN_PATHS)
    assert len(profile.NEW_FILES) == 16 and len(profile.FROZEN_PATHS) == 14 and len(pinned) == 30
    for path, expected in profile.ERA_SHA256.items():
        assert profile.digest(profile.regular_bytes(path)) == expected


@pytest.mark.parametrize("path", sorted(profile.ERA_SHA256))
def test_every_era_file_is_bound_by_digest_before_anything_runs(monkeypatch, path):
    original = profile.reviewed_bytes
    executed = []
    monkeypatch.setattr(profile, "reviewed_bytes", lambda target: original(target) + b" " if target == path else original(target))
    monkeypatch.setattr(profile, "validate_contract_files", lambda: executed.append(True))
    with pytest.raises(ValueError, match=re.escape("unreviewed W03-PLAN-AMEND-3 source: " + path)):
        VALIDATE()
    assert executed == []


@pytest.mark.parametrize("path", ["architecture/w03-plan-v2/README.md", "README.md", None])
def test_a_path_outside_the_era_is_refused_before_it_is_read(monkeypatch, path):
    read = []
    monkeypatch.setattr(profile, "reviewed_bytes", lambda target: read.append(target) or b"")
    with pytest.raises(ValueError, match=re.escape("MET-ENFORCE-037 reviewed bytes are bound: " + str(path))):
        profile._verified(path)
    assert read == []


@pytest.mark.parametrize("path", profile.FROZEN_PATHS)
def test_plan_v2_the_amendments_edge_v5_and_the_cited_files_may_not_change(monkeypatch, path):
    rules = dict(profile._PROJECTION_RULES)
    rules[path] = rules[next(iter(rules))]
    monkeypatch.setattr(profile, "_PROJECTION_RULES", MappingProxyType(rules))
    with pytest.raises(ValueError, match="stay byte-identical"):
        VALIDATE()


@pytest.mark.parametrize("path", ["architecture/w03-plan-v2/plan-v3.json", "architecture/w03-obligation-amendment-1/note.md",
                                  "architecture/w03-obligation-amendment-2/round4/amendment.json",
                                  "architecture/artifact-edges/operator-harness-engineering-v7.json"])
def test_no_file_may_be_added_to_a_frozen_directory_and_no_edge_record_is_published(monkeypatch, path):
    record = copy.deepcopy(profile.authority())
    record["newFiles"][path] = "0" * 64
    monkeypatch.setattr(profile, "authority", lambda: record)
    with pytest.raises(ValueError, match="stay byte-identical"):
        VALIDATE()


@pytest.mark.parametrize("change", ["missing", "extra"])
def test_the_contract_files_are_new_in_this_packet_each_once(monkeypatch, change):
    record = copy.deepcopy(profile.authority())
    if change == "missing":
        del record["newFiles"][profile.REVIEW_BRIEF_PATH]
    else:
        record["newFiles"][profile.AM3_DIR + "review-round5.json"] = "0" * 64
    monkeypatch.setattr(profile, "authority", lambda: record)
    with pytest.raises(ValueError, match="the contract's files are new in this packet, each once"):
        VALIDATE()


@pytest.mark.parametrize("change, message", [
    ("later_file", "the contract directory holds exactly its files and the candidate snapshots"),
    ("missing_folder", "the contract directory holds exactly its files and the candidate snapshots"),
    ("folder_as_file", "the contract directory holds exactly its files and the candidate snapshots"),
    ("executable", "a contract file is a regular file of git mode 100644: " + profile.STATUS_PATH),
    ("symlink", "a contract file is a regular file of git mode 100644: " + profile.README_PATH)])
def test_the_contract_tree_is_closed_and_every_file_is_mode_100644(monkeypatch, change, message):
    tree = dict(profile.reviewed_tree(profile.AM3_DIR))
    folder = profile.AM3_DIR + "candidate1"
    if change == "later_file":
        tree[profile.AM3_DIR + "later.json"] = stat.S_IFREG | 0o644
    elif change == "missing_folder":
        del tree[folder]
    elif change == "folder_as_file":
        tree[folder] = stat.S_IFREG | 0o644
    elif change == "executable":
        tree[profile.STATUS_PATH] = stat.S_IFREG | 0o755
    else:
        tree[profile.README_PATH] = stat.S_IFLNK | 0o777
    monkeypatch.setattr(profile, "reviewed_tree", lambda directory: tree)
    with pytest.raises(ValueError, match=re.escape(message)):
        VALIDATE()


def test_the_contract_tree_is_read_from_the_checkout():
    tree = profile.reviewed_tree(profile.AM3_DIR)
    assert set(tree) == profile.CONTRACT_TREE and len(profile.CONTRACT_TREE) == 16 + 12
    assert all(stat.S_ISREG(tree[path]) and not tree[path] & 0o111 for path in profile.NEW_FILES)


def test_the_contract_directory_must_not_be_a_link(monkeypatch):
    original = profile.reviewed_mode
    monkeypatch.setattr(profile, "reviewed_mode", lambda path: stat.S_IFLNK | 0o777 if path == profile.AM3_DIR[:-1]
                        else original(path))
    with pytest.raises(ValueError, match="the contract directory is a directory, not a link"):
        VALIDATE()


# Synthetic local paths, assembled so this file holds none: each pattern the check refuses, followed by a path.
LOCAL = [b"/Us" + b"ers/someone/x", b"/pri" + b"vate/tmp/x", b"<workspace>/../../Us" + b"ers/x/y"]


@pytest.mark.parametrize("local", LOCAL)
@pytest.mark.parametrize("path", [profile.REVIEW_BRIEF_PATH, LAST_RECORD])
def test_no_contract_file_may_carry_an_absolute_local_path(monkeypatch, path, local):
    if path.endswith(".md"):
        raw = profile.reviewed_bytes(path) + b"\nsee " + local + b"\n"
    else:
        record = _json(path)
        record["checks"].append({"check": "see", "result": local.decode("utf-8")})
        raw = _dump(record)
    _rebind(monkeypatch, {path: raw})
    with pytest.raises(ValueError, match=re.escape("no absolute local path in a contract file: " + path)):
        VALIDATE()


def test_a_bare_prefix_in_a_privacy_statement_is_not_a_path():
    assert profile.local_paths(b"No /Us" + b"ers/, /pri" + b"vate/tmp, /home/, '~/' or local username") == []
    assert profile.local_paths(b"under <scratch>/amend3-contract-review-r1 and <workspace>/harness-onion-npv4") == []
    assert profile.local_paths(b"git -C /Us" + b"ers/name/clone show") == [profile.LOCAL_PATHS[0].pattern]
    assert all(profile.local_paths(profile.reviewed_bytes(path)) == [] for path in profile.NEW_FILES)


@pytest.mark.parametrize("change", ["schema", "work_item", "amendment", "state", "adoption", "adoption_candidate",
                                    "superseded_why", "superseded_instruction", "superseded_candidate", "base",
                                    "review_base", "adopted", "adopted_order", "reviewer", "note", "record_paths",
                                    "non_claims", "closed", "closed_order", "carried_dropped", "carried_order",
                                    "carried_elsewhere", "carried_action", "extra_key"])
def test_the_status_is_closed_and_records_the_adoption(monkeypatch, change):
    status = _status()
    carried = status["carried"]
    if change == "schema":
        status["schemaVersion"] = "planeon.internal.w03-obligation-amendment-3-status/v2"
    elif change == "work_item":
        status["workItem"] = "W03-PLAN-AMEND-2"
    elif change == "amendment":
        status["amendmentId"] = "W03-PLAN-AMEND-4"
    elif change == "state":
        status["status"] = "CONTRACT_CANDIDATE"
    elif change == "adoption":
        status["adoption"]["decision"] += " "
    elif change == "adoption_candidate":
        status["adoption"]["candidate"] = 4
    elif change == "superseded_why":
        status["supersededAdoption"]["why"] = status["supersededAdoption"]["why"].replace("60 s", "30 s")
    elif change == "superseded_instruction":
        status["supersededAdoption"]["instruction"] = ""
    elif change == "superseded_candidate":
        status["supersededAdoption"]["candidate"] = 3
    elif change == "base":
        status["baseMain"] = "0" * 40
    elif change == "review_base":
        status["reviewBase"] = status["baseMain"]
    elif change == "adopted":
        status["adoptedSubject"][profile.AMENDMENT] = "0" * 64
    elif change == "adopted_order":
        status["adoptedSubject"] = dict(reversed(list(status["adoptedSubject"].items())))
    elif change == "reviewer":
        status["independentReviewer"] = "AUTHOR"
    elif change == "note":
        status["readmeStatusNote"] = ""
    elif change == "record_paths":
        status["recordPaths"] = None
    elif change == "non_claims":
        status["nonClaims"].pop()
    elif change == "closed":
        status["closedFindings"]["C4-1"] = "CLOSED in candidate 5"
    elif change == "closed_order":
        status["closedFindings"] = dict(reversed(list(status["closedFindings"].items())))
    elif change == "carried_dropped":
        status["carried"] = carried[1:]
    elif change == "carried_order":
        carried[1], carried[2] = carried[2], carried[1]
    elif change == "carried_elsewhere":
        carried[1]["to"] = "HE-005"
    elif change == "carried_action":
        carried[2]["action"] = ""
    else:
        status["installed"] = False
    _rebind(monkeypatch, {profile.STATUS_PATH: _dump(status)})
    with pytest.raises(ValueError, match="adopted W03-PLAN-AMEND-3 status"):
        VALIDATE()


@pytest.mark.parametrize("path", [profile.AMENDMENT, profile.README_PATH])
def test_an_adopted_file_with_a_wrong_sha256_is_refused(monkeypatch, path):
    _rebind(monkeypatch, {path: profile.reviewed_bytes(path) + b"\n"})
    with pytest.raises(ValueError, match=re.escape("the adopted files are candidate 5: " + path)):
        VALIDATE()


def test_the_adoption_restates_the_decisions_record():
    status = _status()
    assert profile.ADOPTION["candidate"] == 5 and profile.ADOPTION["decision"].startswith(
        "Monitor: RE-ADOPT AMEND-3 candidate 5 for slot 250 (amendment.json ddf5e9ab, README 1e2092e8, ")
    assert profile.SUPERSEDED["candidate"] == 4 and "my candidate-4 adoption is superseded by this" in profile.SUPERSEDED[
        "instruction"]
    assert profile.SUPERSEDED["why"].startswith("Q-HE4D1-D2 = (a): ")
    assert any(text.endswith(profile.SUPERSEDED["why"]) for text in _json(profile.AMENDMENT)["ownerDecisions"])
    assert status["adoption"] == profile.ADOPTION and status["supersededAdoption"] == profile.SUPERSEDED


@pytest.mark.parametrize("change, message", [
    ("count", "five candidates in order"), ("order", "five candidates in order"),
    ("extra_key", "five candidates in order"),
    ("snapshot", "candidate 1 is bound to its snapshot"), ("sha", "candidate 2 is bound to its snapshot"),
    ("kept_dropped", "candidate 3 is bound to its snapshot"), ("kept_twice", "candidate 4 is bound to its snapshot"),
    ("kept_outside", "candidate 1 is bound to its snapshot"), ("adopted_snapshot", "candidate 5 is bound to its snapshot"),
    ("adopted_kept", "candidate 5 is bound to its snapshot"), ("adopted_sha", "candidate 5 is bound to its snapshot")])
def test_each_candidate_is_bound_to_its_snapshot(monkeypatch, change, message):
    status = _status()
    rows = status["candidates"]
    if change == "count":
        rows.pop(0)
    elif change == "order":
        rows[0], rows[1] = rows[1], rows[0]
    elif change == "extra_key":
        rows[2]["subject"] = "candidate 3"
    elif change == "snapshot":
        rows[0]["snapshot"] = profile.AM3_DIR + "candidate2/"
    elif change == "sha":
        rows[1]["sha256"][profile.README_PATH] = "0" * 64
    elif change == "kept_dropped":
        rows[2]["keptCopies"].pop()
    elif change == "kept_twice":
        rows[3]["keptCopies"].append(rows[3]["keptCopies"][0])
    elif change == "kept_outside":
        rows[0]["keptCopies"].append("README.md")
    elif change == "adopted_snapshot":
        rows[4]["snapshot"] = profile.AM3_DIR + "candidate5/"
    elif change == "adopted_kept":
        rows[4]["keptCopies"] = [profile.AMENDMENT]
    else:
        rows[4]["sha256"][profile.AMENDMENT] = "0" * 64
    _rebind(monkeypatch, {profile.STATUS_PATH: _dump(status)})
    with pytest.raises(ValueError, match=re.escape(message)):
        VALIDATE()


@pytest.mark.parametrize("change, message", [
    ("count", "four review rounds in order"), ("verdict", "four review rounds in order"),
    ("round_number", "four review rounds in order"), ("subject_candidate", "four review rounds in order"),
    ("extra_key", "four review rounds in order"),
    ("record_sha", "review round 1 is bound to its record"), ("record_path", "review round 2 is bound to its record"),
    ("subject_sha", "review round 3 is bound to its record"), ("snapshot", "review round 4 is bound to its record")])
def test_each_round_is_bound_to_its_record_and_its_subject_candidate(monkeypatch, change, message):
    status = _status()
    rounds = status["rounds"]
    if change == "count":
        rounds.pop()
    elif change == "verdict":
        rounds[1]["verdict"] = "CHANGES_REQUIRED"
    elif change == "round_number":
        rounds[2]["round"] = 2
    elif change == "subject_candidate":
        rounds[3]["candidate"] = 4
    elif change == "extra_key":
        rounds[0]["subjectCommit"] = "0" * 40
    elif change == "record_sha":
        rounds[0]["recordSha256"] = "0" * 64
    elif change == "record_path":
        rounds[1]["record"] = profile.AM3_DIR + "review-round3.json"
    elif change == "subject_sha":
        rounds[2]["subjectSha256"][profile.AMENDMENT] = "0" * 64
    else:
        rounds[3]["snapshot"] = profile.AM3_DIR + "candidate4/"
    _rebind(monkeypatch, {profile.STATUS_PATH: _dump(status)})
    with pytest.raises(ValueError, match=re.escape(message)):
        VALIDATE()


@pytest.mark.parametrize("number, change, message", [
    (1, lambda record: record.__setitem__("verdict", "PASS_FOR_ADOPTION"), "review round 1 is bound to its record"),
    (2, lambda record: record.__setitem__("subject", record["subject"].replace("candidate 2", "candidate 3")),
     "review round 2 is bound to its record"),
    (4, lambda record: record.__setitem__("subject", record["subject"].replace("ddf5e9", "ddf5e8")),
     "review round 4 is bound to its record"),
    (3, lambda record: record["findings"].pop(), "review round 3 is bound to its record"),
    (4, lambda record: record["actions"].__setitem__("networkAccessed", "docs only"), "review round 4 is bound to its record"),
    (2, lambda record: record["priorFindings"][0].__setitem__("status", "PARTLY"),
     "review round 2 fixed every finding of round 1"),
    (3, lambda record: record["priorFindings"].pop(), "review round 3 fixed every finding of round 2"),
    (4, lambda record: record["changesSinceRound3"].pop("c3ToC4"), "round 4 states the c3->c4->c5 delta")])
def test_each_record_matches_its_status_row(monkeypatch, number, change, message):
    _rebind_record(monkeypatch, number, change)
    with pytest.raises(ValueError, match=re.escape(message)):
        VALIDATE()


def test_round_4_reviewed_the_adopted_candidate_5():
    status = _status()
    last = status["rounds"][-1]
    assert (last["round"], last["verdict"], last["candidate"], last["snapshot"]) == (4, "PASS_FOR_ADOPTION", 5, None)
    assert last["subjectSha256"] == profile.ADOPTED_SHA256 == status["candidates"][-1]["sha256"]
    assert [row["recordSha256"][:8] for row in status["rounds"][2:]] == ["6fba6636", "f38a2b7b"]
    assert [len(row["keptCopies"]) for row in status["candidates"]] == [2, 2, 2, 2, 0]


@pytest.mark.parametrize("change", ["c4_extra_change", "c4_without_source", "c4_other_source", "c4_readme"])
def test_candidate_5_is_candidate_3_with_only_the_stated_delta(monkeypatch, change):
    snapshot = profile.AM3_DIR + "candidate4/"
    if change == "c4_readme":
        raw = profile.reviewed_bytes(snapshot + profile.README_PATH).replace(b"| NP-9 |", b"| NP-9  |", 1)
        assert raw != profile.reviewed_bytes(snapshot + profile.README_PATH)
        _rebind_candidate(monkeypatch, 4, profile.README_PATH, raw)
    else:
        candidate4 = _json(snapshot + profile.AMENDMENT)
        if change == "c4_extra_change":
            candidate4["carried"][0]["to"] += " "
        elif change == "c4_without_source":
            del candidate4["carried"][1]["source"]
        else:
            candidate4["carried"][1]["source"] = "architecture/native-profile-v4/README.md:495"
        _rebind_candidate(monkeypatch, 4, profile.AMENDMENT, _dump(candidate4))
    with pytest.raises(ValueError, match=re.escape("candidate 5 is candidate 3 with only the stated c3->c4->c5 delta")):
        VALIDATE()


def test_the_readme_keeps_its_candidate_status_line(monkeypatch):
    monkeypatch.setattr(profile, "CANDIDATE_STATUS", "Status: **ADOPTED**")
    with pytest.raises(ValueError, match="the README keeps its reviewed candidate status line"):
        VALIDATE()


def test_decision_ids_are_read_as_the_records_write_them():
    assert profile.decision_ids("Q-HE4D1-2, 3, 5, 6, 7, 10, 11 and 12 = all (a), as in the dossier.") == {
        "Q-HE4D1-%d" % n for n in (2, 3, 5, 6, 7, 10, 11, 12)}
    assert profile.decision_ids("Q-HE4D1-8 and -9 = (a): the next W03 plan amendment") == {"Q-HE4D1-8", "Q-HE4D1-9"}
    assert profile.decision_ids("Q-HE4D1-D2 = (a): keep the 60 s cadence (Q-HE4D1-6 (a))") == {"Q-HE4D1-D2", "Q-HE4D1-6"}
    assert profile.decision_ids("under Q-HE4-3/4 (a); Q-A3-7 (a)") == {"Q-HE4-3/4", "Q-A3-7"}


def _mutate_amendment(value, change):
    """Mutate a parsed amendment; return the (obligation, change) sequence the mutated rows restate, if it changed."""
    rows = value["changes"]
    sec4 = _rows(value, "SEC-4")[0]
    if change == "after_reordered":
        value["after"].reverse()
    elif change == "after_digest":
        value["after"][1]["sha256"] = "sha256:" + "0" * 64
    elif change == "after_dropped":
        value["after"].pop()
    elif change == "after_object":
        value["after"] = value["after"][0]
    elif change == "amends_digest":
        value["amends"]["sha256"] = "sha256:" + "0" * 64
    elif change == "schema":
        value["schemaVersion"] = "planeon.internal.w03-obligation-amendment/v2"
    elif change == "unknown_kind":
        rows[0]["change"] = "NARROWED"
    elif change == "extra_kind":
        value["changeKinds"]["NARROWED"] = "Ownership narrowed, as in amendment 1."
    elif change == "missing_kind":
        del value["changeKinds"]["REFINED"]
    elif change == "rows_reordered":
        rows[0], rows[1] = rows[1], rows[0]
    elif change == "added_plan":
        rows[0]["obligation"] = "NP-1"
    elif change == "added_amendment_1":
        rows[0]["obligation"] = "I07-6"
    elif change == "added_amendment_2":
        rows[1]["obligation"] = "OBS-RBAC-1"
    elif change == "added_twice":
        rows[1]["obligation"] = "OBS-HOSTPOL-1"
    elif change == "added_empty":
        rows[1]["packets"] = []
        rows[1]["shares"] = {}
    elif change == "share_unlisted":
        rows[0]["shares"]["HE-005"] = "the enrolled host"
    elif change == "share_empty":
        rows[1]["shares"]["T04"] = " "
    elif change == "replaced_absent":
        sec4["replaced"] = "words that occur nowhere in the share"
        sec4["shares"]["HE-003"] = _earlier_share("SEC-4")
    elif change == "replaced_twice":
        share = _earlier_share("SEC-4")
        assert share.count("the ") >= 2
        sec4["replaced"] = "the "
        sec4["shares"]["HE-003"] = share.replace("the ", sec4["replacement"])
    elif change == "share_one_byte":
        sec4["shares"]["HE-003"] = _flip(sec4["shares"]["HE-003"], 40)
    elif change == "packets_dropped":
        sec4["packets"].remove("T04")
    elif change == "packets_reordered":
        sec4["packets"].reverse()
    elif change == "corrects_digest":
        sec4["corrects"]["sha256"] = "sha256:" + "0" * 64
    elif change == "corrects_amendment_2":
        sec4["corrects"]["path"], sec4["corrects"]["sha256"] = value["after"][1]["path"], value["after"][1]["sha256"]
    elif change == "row_lines":
        sec4["corrects"]["rowLines"] = "40-61"
    elif change == "row_lines_other":
        sec4["corrects"]["rowLines"] = _rows(value, "HI-7")[0]["corrects"]["rowLines"]
        sec4["corrects"]["shareLine"] = _rows(value, "HI-7")[0]["corrects"]["shareLine"]
    elif change == "share_line":
        sec4["corrects"]["shareLine"] += 1
    elif change == "share_line_outside":
        sec4["corrects"]["shareLine"] = 62
    elif change == "share_named":
        sec4["corrects"]["share"] = sec4["corrects"]["share"].replace("amendment 1's", "amendment 2's")
    elif change == "second_row_on_the_original":
        rows.insert(3, copy.deepcopy(sec4))
        return [(row["obligation"], row["change"]) for row in rows]
    elif change == "decision_count":
        value["ownerDecisions"].pop(12)
    elif change == "decision_duplicate":
        value["ownerDecisions"][12] = value["ownerDecisions"][11]
    elif change == "decision_missing":
        # Q-A3-2 (a), which OBS-HOSTPOL-1's source cites, is recorded in this entry only.
        assert value["ownerDecisions"][7].startswith("Monitor, owner-delegated (2026-10-18, verbatim): Q-A3-2 (a): ")
        value["ownerDecisions"][7] = "Monitor, owner-delegated (2026-10-18, verbatim): a note without an id."
    elif change == "uncited_row":
        rows[0]["source"] += "; owner decision Q-HE4D1-99 (a)"
    elif change == "uncited_scope":
        value["packetScopes"][0]["decisions"][0]["id"] = "Q-HE4D1-13"
    elif change == "uncited_hand_off":
        value["packetScopes"][0]["handOffs"][0]["decision"] = "Q-HE4D1-14 (a)"
    elif change == "uncited_carried":
        value["carried"][4]["decision"] = "monitor decision Q-A3-9 (a)"
    elif change == "recorded_elsewhere_other":
        rows[1]["source"] = rows[1]["source"].replace("Q-NP4D-10", "Q-NP4D-11")
    else:
        raise AssertionError(change)
    return None


@pytest.mark.parametrize("change, message", [
    ("after_reordered", "the amendment binds plan v2 and amendments 1 and 2, in order, by their bytes"),
    ("after_digest", "the amendment binds plan v2 and amendments 1 and 2, in order, by their bytes"),
    ("after_dropped", "the amendment binds plan v2 and amendments 1 and 2, in order, by their bytes"),
    ("after_object", "the amendment binds plan v2 and amendments 1 and 2, in order, by their bytes"),
    ("amends_digest", "the amendment binds plan v2 and amendments 1 and 2, in order, by their bytes"),
    ("schema", "the amendment binds plan v2 and amendments 1 and 2, in order, by their bytes"),
    ("unknown_kind", "the closed change kinds"), ("extra_kind", "the closed change kinds"),
    ("missing_kind", "the closed change kinds"),
    ("rows_reordered", "the amendment's four changes, in order"),
    ("added_plan", "an ADDED row adds an obligation absent from plan v2 and amendments 1 and 2: NP-1"),
    ("added_amendment_1", "an ADDED row adds an obligation absent from plan v2 and amendments 1 and 2: I07-6"),
    ("added_amendment_2", "an ADDED row adds an obligation absent from plan v2 and amendments 1 and 2: OBS-RBAC-1"),
    ("added_twice", "an ADDED row adds an obligation absent from plan v2 and amendments 1 and 2: OBS-HOSTPOL-1"),
    ("added_empty", "an ADDED row adds an obligation absent from plan v2 and amendments 1 and 2: NP-9"),
    ("share_unlisted", "every share names a packet in its row's list: OBS-HOSTPOL-1"),
    ("share_empty", "every share names a packet in its row's list: NP-9"),
    ("replaced_absent", "a SHARE_CORRECTED row corrects one located share of a bound amendment as quoted: SEC-4"),
    ("replaced_twice", "a SHARE_CORRECTED row corrects one located share of a bound amendment as quoted: SEC-4"),
    ("share_one_byte", "a SHARE_CORRECTED row corrects one located share of a bound amendment as quoted: SEC-4"),
    ("packets_dropped", "a SHARE_CORRECTED row corrects one located share of a bound amendment as quoted: SEC-4"),
    ("packets_reordered", "a SHARE_CORRECTED row corrects one located share of a bound amendment as quoted: SEC-4"),
    ("corrects_digest", "a SHARE_CORRECTED row corrects one located share of a bound amendment as quoted: SEC-4"),
    ("corrects_amendment_2", "a SHARE_CORRECTED row corrects one located share of a bound amendment as quoted: SEC-4"),
    ("row_lines", "a SHARE_CORRECTED row corrects one located share of a bound amendment as quoted: SEC-4"),
    ("row_lines_other", "a SHARE_CORRECTED row corrects one located share of a bound amendment as quoted: SEC-4"),
    ("share_line", "a SHARE_CORRECTED row corrects one located share of a bound amendment as quoted: SEC-4"),
    ("share_line_outside", "a SHARE_CORRECTED row corrects one located share of a bound amendment as quoted: SEC-4"),
    ("share_named", "a SHARE_CORRECTED row corrects one located share of a bound amendment as quoted: SEC-4"),
    ("second_row_on_the_original",
     "a SHARE_CORRECTED row corrects one located share of a bound amendment as quoted: SEC-4"),
    ("decision_count", "the 17 recorded decisions are unique non-empty texts"),
    ("decision_duplicate", "the 17 recorded decisions are unique non-empty texts"),
    ("decision_missing", "every decision a change, scope, hand-off or carried item cites is recorded"),
    ("uncited_row", "every decision a change, scope, hand-off or carried item cites is recorded"),
    ("uncited_scope", "every decision a change, scope, hand-off or carried item cites is recorded"),
    ("uncited_hand_off", "every decision a change, scope, hand-off or carried item cites is recorded"),
    ("uncited_carried", "every decision a change, scope, hand-off or carried item cites is recorded"),
    ("recorded_elsewhere_other", "every decision a change, scope, hand-off or carried item cites is recorded")])
def test_every_amendment_rule_is_checked(monkeypatch, change, message):
    value = _json(profile.AMENDMENT)
    sequence = _mutate_amendment(value, change)
    if change.startswith("added_") or sequence is not None:
        monkeypatch.setattr(profile, "CHANGES", tuple(sequence or ((row["obligation"], row["change"])
                                                                   for row in value["changes"])))
    _rebind(monkeypatch, {profile.AMENDMENT: _dump(value)})
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.validate_amendment()


def test_rows_for_one_obligation_apply_in_order(monkeypatch):
    """A second SHARE_CORRECTED row for the same share corrects the corrected share, not the earlier amendment's."""
    value = _json(profile.AMENDMENT)
    sec4 = _rows(value, "SEC-4")[0]
    second = copy.deepcopy(sec4)
    corrected = sec4["shares"]["HE-003"]
    second["replaced"] = "refuses a signed I04 port below 1024"
    second["replacement"] = "refuses a signed I04 port under 1024"
    assert corrected.count(second["replaced"]) == 1 and _earlier_share("SEC-4").count(second["replaced"]) == 0
    second["shares"] = {"HE-003": corrected.replace(second["replaced"], second["replacement"])}
    value["changes"].insert(3, second)
    monkeypatch.setattr(profile, "CHANGES", tuple((row["obligation"], row["change"]) for row in value["changes"]))
    _rebind(monkeypatch, {profile.AMENDMENT: _dump(value)})
    assert profile.validate_amendment() is None


def test_the_rules_hold_over_the_adopted_amendment_and_its_inputs():
    record = _json(profile.AMENDMENT)
    lists, known = profile._registers()
    assert [row["obligation"] for row in record["changes"] if row["change"] == "ADDED"] == ["OBS-HOSTPOL-1", "NP-9"]
    assert not {"OBS-HOSTPOL-1", "NP-9"} & known
    for name in ("SEC-4", "HI-7"):
        row = _rows(record, name)[0]
        earlier = _earlier_share(name)
        assert earlier.count(row["replaced"]) == 1
        assert row["shares"] == {"HE-003": earlier.replace(row["replaced"], row["replacement"])}
        assert row["packets"] == lists[name] == ["HE-002S", "HE-003", "HE-004A", "HE-005", "HE-006", "HE-007", "HE-008",
                                                 "T04"]
    decided = {name for text in record["ownerDecisions"] for name in profile.decision_ids(text)}
    assert {"Q-HE4D1-%d" % n for n in range(1, 13)} <= decided and "Q-NP4D-10" not in decided
    assert profile.validate_amendment() is None and profile.validate_packet_scopes() is None
    assert profile.validate_citations() is None


def _mutate_scope(value, change):
    scope = value["packetScopes"][0]
    if change == "not_a_part":
        scope["packet"] = "HE-004D3"
    elif change == "other_packet":
        scope["packet"] = "HE-005"
    elif change == "part_of":
        scope["partOf"] = "HE-005"
    elif change == "extra_key":
        scope["status"] = "DONE"
    elif change == "obligation_unlisted":
        scope["obligations"].append("SEC-4")
    elif change == "obligations_empty":
        scope["obligations"] = []
    elif change == "summary_path":
        scope["summaryIn"] = scope["summaryIn"].replace("amendment-2", "amendment-1")
    elif change == "summary_lines":
        scope["summaryIn"] = scope["summaryIn"].replace(":57-58", ":56-57")
    elif change == "summary_past_end":
        scope["summaryIn"] = scope["summaryIn"].replace(":57-58", ":57-345")
    elif change == "decision_twice":
        scope["decisions"][1]["id"] = scope["decisions"][0]["id"]
    elif change == "decision_empty":
        scope["decisions"][2]["option"] = ""
    elif change == "hand_off_not_a_packet":
        scope["handOffs"][0]["to"] = "the operator"
    elif change == "hand_off_no_decision":
        scope["handOffs"][1]["decision"] = "carried"
    elif change == "hand_off_key":
        scope["handOffs"][0]["owner"] = "HE-008"
    elif change == "residuals_empty":
        scope["residuals"] = []
    else:
        raise AssertionError(change)


@pytest.mark.parametrize("change, message", [
    ("not_a_part", "a packet scope is a part of amendment 2's HE-004: HE-004D3"),
    ("other_packet", "a packet scope is a part of amendment 2's HE-004: HE-005"),
    ("part_of", "a packet scope is a part of amendment 2's HE-004: HE-004D1"),
    ("extra_key", "a packet scope is a part of amendment 2's HE-004: HE-004D1"),
    ("obligation_unlisted", "each scoped obligation names the part after this amendment: HE-004D1"),
    ("obligations_empty", "each scoped obligation names the part after this amendment: HE-004D1"),
    ("summary_path", "the scope's summaryIn is the part's lines in amendment 2: HE-004D1"),
    ("summary_lines", "the scope's summaryIn is the part's lines in amendment 2: HE-004D1"),
    ("summary_past_end", "the scope's summaryIn is the part's lines in amendment 2: HE-004D1"),
    ("decision_twice", "the scope's decisions are named once each: HE-004D1"),
    ("decision_empty", "the scope's decisions are named once each: HE-004D1"),
    ("hand_off_not_a_packet", "every hand-off names a packet and a decision: HE-004D1"),
    ("hand_off_no_decision", "every hand-off names a packet and a decision: HE-004D1"),
    ("hand_off_key", "every hand-off names a packet and a decision: HE-004D1"),
    ("residuals_empty", "the scope's residuals: HE-004D1")])
def test_every_packet_scope_rule_is_checked(monkeypatch, change, message):
    value = _json(profile.AMENDMENT)
    _mutate_scope(value, change)
    _rebind(monkeypatch, {profile.AMENDMENT: _dump(value)})
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.validate_packet_scopes()


def test_the_citations_are_the_44_reviewed_ranges():
    cited = profile.citations(_json(profile.AMENDMENT))
    assert len(cited) == 47 and len(set(cited)) == profile.CITED_RANGES == 44
    assert ("architecture/native-profile-v4/README.md", 494, 494) in cited
    assert ("docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md", 92, 94) in cited
    assert ("architecture/artifact-edges/operator-harness-engineering-v5.json", 497, 529) in cited
    assert profile.citations({"a": "see architecture/w03-plan-v2/plan.json:287, row :284-292; sha256:2a98e2 and :7a"}) == [
        ("architecture/w03-plan-v2/plan.json", 287, 287), ("architecture/w03-plan-v2/plan.json", 284, 292)]


@pytest.mark.parametrize("change, message", [
    ("past_end", "every file:line citation in the amendment resolves at the base"),
    ("zero", "every file:line citation in the amendment resolves at the base"),
    ("reversed", "every file:line citation in the amendment resolves at the base"),
    ("outside_era", "every file:line citation in the amendment resolves at the base"),
    ("bare_first", "every file:line citation in the amendment resolves at the base"),
    ("one_more", "every file:line citation in the amendment resolves at the base"),
    ("device_inode_line", "carried[1] cites native-profile v4's device-and-inode rule"),
    ("device_inode_dropped", "carried[1] cites native-profile v4's device-and-inode rule")])
def test_every_citation_resolves_at_the_base(monkeypatch, change, message):
    value = _json(profile.AMENDMENT)
    raw = _dump(value).decode("utf-8")
    if change == "past_end":
        assert raw.count("native-profile-v4/status.json:198-202") == 2
        raw = raw.replace("native-profile-v4/status.json:198-202", "native-profile-v4/status.json:198-217")
    elif change == "zero":
        raw = raw.replace("native-profile-v4/status.json:198-202", "native-profile-v4/status.json:0-202")
    elif change == "reversed":
        raw = raw.replace("native-profile-v4/status.json:198-202", "native-profile-v4/status.json:202-198")
    elif change == "outside_era":
        raw = raw.replace("docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md:92-94", "docs/alpha-2/OTHER_READINESS.md:92-94")
    elif change == "bare_first":
        value["carried"][4]["to"] = ":12 " + value["carried"][4]["to"]
        raw = _dump(value).decode("utf-8")
    elif change == "one_more":
        value["carried"][4]["to"] += " (architecture/w03-plan-v2/plan.json:1)"
        raw = _dump(value).decode("utf-8")
    elif change == "device_inode_line":
        value["carried"][1]["source"] = "architecture/native-profile-v4/README.md:495"
        raw = _dump(value).decode("utf-8")
    else:
        del value["carried"][1]["source"]
        value["carried"][4]["to"] += " (architecture/native-profile-v4/README.md:494)"
        raw = _dump(value).decode("utf-8")
    _rebind(monkeypatch, {profile.AMENDMENT: raw.encode("utf-8")})
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.validate_citations()


def test_the_device_and_inode_rule_is_the_cited_line():
    path, line, rule = profile.DEVICE_INODE
    assert _json(profile.AMENDMENT)["carried"][1]["source"] == "architecture/native-profile-v4/README.md:494"
    assert rule in profile.reviewed_bytes(path).decode("utf-8").split("\n")[line - 1]
    lines = profile.reviewed_bytes(profile.NP4_README).decode("utf-8").split("\n")
    assert "Q-NP4D-10" in "\n".join(lines[301:303])


def test_a_later_successor_leaves_this_era_valid_through_projection(monkeypatch):
    original, reviewed = profile.regular_bytes, profile.reviewed_bytes
    paths = (profile.AMENDMENT_2, profile.NP4_README, profile.STATUS_PATH)
    era = {path: reviewed(path) for path in paths}
    later = {path: era[path] + b"\n" for path in paths}
    monkeypatch.setattr(profile, "regular_bytes", lambda path: later.get(path) or original(path))
    with pytest.raises(ValueError):
        VALIDATE()
    monkeypatch.setattr(profile, "reviewed_bytes", lambda path: era[path] if path in later else reviewed(path))
    assert VALIDATE() is None
    tree = profile.reviewed_tree(profile.AM3_DIR)
    monkeypatch.setattr(profile, "reviewed_tree", lambda directory: {**tree, profile.AM3_DIR + "later.json": 0o100644})
    with pytest.raises(ValueError, match="holds exactly its files"):
        VALIDATE()
    monkeypatch.setattr(profile, "reviewed_tree", lambda directory: tree)
    assert VALIDATE() is None


def test_reviewed_bytes_is_the_only_semantic_read():
    tree = ast.parse(profile.regular_bytes(profile.VALIDATOR_PATH))
    names = {"_parents", "_verified", "_json", "_lines", "_holds", "_bound", "_texts", "local_paths", "_strings", "citations",
             "decision_ids", "_has_lines", "_value", "_registers", "validate_contract_files", "validate_amendment_3_status",
             "_corrects", "validate_amendment", "validate_packet_scopes", "validate_citations", "validate_w03_plan_amend_3"}
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
    layer checked served as checked, and every other file read refused, the whole check still holds."""
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
