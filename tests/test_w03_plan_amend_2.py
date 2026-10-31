"""Exact source lineage for MET-ENFORCE-032; W03 obligation-register amendment 2: plan v2's HE-004 refined into its parts after amendment 1, and operator edge record v4, with every rule checked in the validator."""
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

from scripts import validate_w03_plan_amend_2 as profile
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
    # The newer MET-MAS-004 layer is projected away before this layer's payload checks.
    return profile.successor.historical_catalog(packets())


def changed_test():
    return next(path for path in profile._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert profile.validate() is None
    current = packets()
    accepted = profile.historical_catalog(current)
    assert len(current) == 273 and len(accepted) == 243
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
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET,
                                            profile.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET}
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


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "la2_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = profile.historical_bytes(path, raw) if route in ("current_test", "old_bytes") else None
    current_packets = packets() if route == "catalog" else None
    layer = layer_packets() if route == "payloads" else None
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
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
    with pytest.raises(ValueError, match="w03 plan amendment 2 history authority digest"):
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
    assert len(profile.historical_catalog(current)) == 243


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
    assert len(profile.historical_catalog(current)) == 243
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
    assert len(rules) == 244 and len(parsed) == 243
    assert profile._packet_rules() is rules and len(parsed) == 243
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
    with pytest.raises(ValueError, match="w03 plan amendment 2 history authority digest"):
        profile.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = layer_packets()
    profile.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "w03-plan-amend-2-authority.json").write_bytes(
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
    # The newer MET-MAS-004 layer refuses a mutated validator before this layer.
    with pytest.raises(ValueError, match="unreviewed current source: scripts/validate_w03_plan_amend_2.py"):
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
            assert all("validate_" not in alias.name or alias.name == "validate_topology_coordination"
                       for alias in node.names)


def _count_authority_reads(monkeypatch):
    counts = {}
    for module in (profile.successor, profile, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner):
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
    expected = {module.__name__: 1 for module in (profile.successor, profile, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner)}
    if route == "current_test":
        # The forward route reads this layer's newest bytes and then projects them forward once more.
        assert all(counts[name] >= 1 for name in expected) and set(counts) == set(expected)
    else:
        assert counts == expected


def _dump(value):
    return (json.dumps(value, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def _rebind(monkeypatch, served):
    """Serve changed bytes for some paths and re-pin their era digests, so the checks behind the digest binding run."""
    original = profile.reviewed_bytes
    pins = dict(profile.ERA_SHA256)
    for path, raw in served.items():
        if path in pins:
            pins[path] = profile.digest(raw)
    monkeypatch.setattr(profile, "ERA_SHA256", MappingProxyType(pins))
    monkeypatch.setattr(profile, "reviewed_bytes", lambda target: served[target] if target in served else original(target))


def _load(path):
    return json.loads(profile.reviewed_bytes(path))


def _status():
    return _load(profile.STATUS_PATH)


def _rebind_record(monkeypatch, number, change):
    """Serve a changed review record with its status row's record digest re-pinned."""
    path = profile.AM2_DIR + "review-round%d.json" % number
    record = _load(path)
    change(record)
    status = _status()
    status["rounds"][number - 1]["recordSha256"] = profile.digest(_dump(record))
    _rebind(monkeypatch, {path: _dump(record), profile.STATUS_PATH: _dump(status)})


def _rebind_round_copy(monkeypatch, number, path, raw):
    """Serve a changed round snapshot with its record's subject, the record digest and the status row re-pinned."""
    copy_path = profile.AM2_DIR + "round%d/" % number + path
    record_path = profile.AM2_DIR + "review-round%d.json" % number
    record = _load(record_path)
    record["subject"][path] = profile.digest(raw)
    status = _status()
    row = status["rounds"][number - 1]
    row["subjectSha256"][path] = profile.digest(raw)
    row["recordSha256"] = profile.digest(_dump(record))
    _rebind(monkeypatch, {copy_path: raw, record_path: _dump(record), profile.STATUS_PATH: _dump(status)})


def _rows(value, obligation, change=None):
    return [row for row in value["changes"] if row["obligation"] == obligation and change in (None, row["change"])]


def test_the_amendment_holds_for_this_era():
    assert profile.validate_w03_plan_amend_2() is None


def test_every_subject_file_round_record_and_read_input_is_pinned():
    pinned = set(profile.ERA_SHA256)
    status = _status()
    assert set(profile.SUBJECT) | {profile.STATUS_PATH, profile.AM2_DIR + "REVIEW_BRIEF.md"} <= pinned
    assert {row["record"] for row in status["rounds"]} <= pinned
    assert {row["snapshot"] + path for row in status["rounds"] for path in row["keptCopies"]} <= pinned
    assert set(profile.FROZEN_PATHS) == {profile.PLAN_V2, profile.AMENDMENT_1, profile.V3_EDGE} | {
        row[0] for row in profile.NEW_ROWS} <= pinned
    assert all(path in profile.FROZEN_PATHS or path.startswith(profile.AM2_DIR) or path in (profile.V4_EDGE, profile.V4_README)
               for path in pinned)
    assert len(profile.NEW_ROWS) == 12 and len(profile.FROZEN_PATHS) == 15 and len(pinned) == 34
    for path, expected in profile.ERA_SHA256.items():
        assert profile.digest(profile.reviewed_bytes(path)) == expected


@pytest.mark.parametrize("path", sorted(profile.ERA_SHA256))
def test_every_era_file_is_bound_by_digest_before_anything_runs(monkeypatch, path):
    original = profile.reviewed_bytes
    executed = []
    monkeypatch.setattr(profile, "reviewed_bytes", lambda target: original(target) + b" " if target == path else original(target))
    monkeypatch.setattr(profile, "validate_amendment_2_status", lambda: executed.append(True))
    with pytest.raises(ValueError, match=re.escape("unreviewed W03-PLAN-AMEND-2 source: " + path)):
        profile.validate_w03_plan_amend_2()
    assert executed == []


@pytest.mark.parametrize("path", ["architecture/w03-plan-v2/README.md", "README.md", None])
def test_a_path_outside_the_era_is_refused_before_it_is_read(monkeypatch, path):
    read = []
    monkeypatch.setattr(profile, "reviewed_bytes", lambda target: read.append(target) or b"")
    with pytest.raises(ValueError, match=re.escape("W03-PLAN-AMEND-2 reviewed bytes are bound: " + str(path))):
        profile._verified(path)
    assert read == []


@pytest.mark.parametrize("path", profile.FROZEN_PATHS)
def test_plan_v2_amendment_1_edge_v3_and_the_providers_may_not_change(monkeypatch, path):
    rules = dict(profile._PROJECTION_RULES)
    rules[path] = rules[next(iter(rules))]
    monkeypatch.setattr(profile, "_PROJECTION_RULES", MappingProxyType(rules))
    with pytest.raises(ValueError, match="plan v2, amendment 1, edge record v3 and the registered provider files stay"):
        profile.validate_w03_plan_amend_2()


@pytest.mark.parametrize("change", ["schema", "work_item", "amendment", "state", "adoption", "base", "review_base",
                                    "adopted", "adopted_order", "reviewer", "note", "non_claims", "closed",
                                    "carried_dropped", "carried_order", "carried_elsewhere", "extra_key"])
def test_the_status_is_closed_and_records_the_adoption(monkeypatch, change):
    status = _status()
    carried = status["carried"]
    if change == "schema":
        status["schemaVersion"] = "planeon.internal.w03-obligation-amendment-2-status/v2"
    elif change == "work_item":
        status["workItem"] = "W03-PLAN-AMEND"
    elif change == "amendment":
        status["amendmentId"] = "W03-PLAN-AMEND-1"
    elif change == "state":
        status["status"] = "CONTRACT_CANDIDATE"
    elif change == "adoption":
        status["adoption"]["decidedBy"] = "the author"
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
        status["recordPaths"] = ""
    elif change == "non_claims":
        status["nonClaims"].pop()
    elif change == "closed":
        status["closedFindings"]["C3-1"] = "CLOSED in round 3"
    elif change == "carried_dropped":
        status["carried"] = carried[1:]
    elif change == "carried_order":
        carried[0], carried[1] = carried[1], carried[0]
    elif change == "carried_elsewhere":
        carried[0]["to"] = "wording only"
    else:
        status["installed"] = False
    _rebind(monkeypatch, {profile.STATUS_PATH: _dump(status)})
    with pytest.raises(ValueError, match="adopted W03-PLAN-AMEND-2 status"):
        profile.validate_w03_plan_amend_2()


def test_the_adopted_files_are_candidate_4(monkeypatch):
    raw = profile.reviewed_bytes(profile.V4_README) + b"\n"
    _rebind(monkeypatch, {profile.V4_README: raw})
    with pytest.raises(ValueError, match=re.escape("the adopted files are candidate 4: " + profile.V4_README)):
        profile.validate_w03_plan_amend_2()


@pytest.mark.parametrize("change, message", [
    ("count", "three review rounds in order"), ("last_verdict", "three review rounds in order"),
    ("round_number", "three review rounds in order"), ("extra_key", "three review rounds in order"),
    ("record_sha", "review round 1 is bound"), ("record_path", "review round 2 is bound"),
    ("snapshot", "review round 1 is bound"), ("subject_sha", "review round 2 is bound"),
    ("kept_outside", "review round 1 is bound"), ("kept_dropped", "review round 3 is bound"),
    ("kept_identical", "review round 3 is bound"), ("kept_twice", "review round 2 is bound")])
def test_each_round_is_bound_to_its_record_and_its_exact_subject_bytes(monkeypatch, change, message):
    status = _status()
    rounds = status["rounds"]
    if change == "count":
        rounds.pop(0)
    elif change == "last_verdict":
        rounds[2]["verdict"] = "CHANGES_REQUIRED"
    elif change == "round_number":
        rounds[1]["round"] = 3
    elif change == "extra_key":
        rounds[2]["subjectCommit"] = "0" * 40
    elif change == "record_sha":
        rounds[0]["recordSha256"] = "0" * 64
    elif change == "record_path":
        rounds[1]["record"] = profile.AM2_DIR + "review-round3.json"
    elif change == "snapshot":
        rounds[0]["snapshot"] = profile.AM2_DIR + "round2/"
    elif change == "subject_sha":
        rounds[1]["subjectSha256"][profile.V4_EDGE] = "0" * 64
    elif change == "kept_outside":
        rounds[0]["keptCopies"].append("README.md")
    elif change == "kept_dropped":
        rounds[2]["keptCopies"].pop()
    elif change == "kept_identical":
        rounds[2]["keptCopies"].append(profile.V4_EDGE)
    else:
        rounds[1]["keptCopies"].append(rounds[1]["keptCopies"][0])
    _rebind(monkeypatch, {profile.STATUS_PATH: _dump(status)})
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.validate_w03_plan_amend_2()


@pytest.mark.parametrize("number, key, value", [(1, "verdict", "PASS_FOR_ADOPTION"), (2, "subject", {}),
                                                (3, "verdict", "CHANGES_REQUIRED")])
def test_each_record_matches_its_status_row(monkeypatch, number, key, value):
    _rebind_record(monkeypatch, number, lambda record: record.__setitem__(key, value))
    with pytest.raises(ValueError, match="review round %d is bound to its record" % number):
        profile.validate_w03_plan_amend_2()


@pytest.mark.parametrize("change", ["id", "other_text", "no_fix"])
def test_candidate_4_is_candidate_3_with_only_c3_1_applied(monkeypatch, change):
    path = profile.AM2_DIR + "round3/" + profile.AMENDMENT
    candidate3 = _load(path)
    if change == "id":
        candidate3["id"] = "W03-PLAN-AMEND-3"
    elif change == "other_text":
        _rows(candidate3, "OBS-INV-1")[0]["text"] += " "
    else:
        _rows(candidate3, "OBS-RBAC-1")[0]["text"] = _rows(_load(profile.AMENDMENT), "OBS-RBAC-1")[0]["text"]
    # Indented differently, so the round copy's bytes still differ from the adopted file's.
    raw = (json.dumps(candidate3, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    _rebind_round_copy(monkeypatch, 3, profile.AMENDMENT, raw)
    with pytest.raises(ValueError, match="candidate 4 is candidate 3 with only C3-1's OBS-RBAC-1 text applied"):
        profile.validate_w03_plan_amend_2()


def test_the_readme_differs_from_candidate_3_only_in_the_c3_1_row(monkeypatch):
    raw = profile.reviewed_bytes(profile.AM2_DIR + "round3/" + profile.README_PATH).replace(b"| NP-3 |", b"| NP-3  |", 1)
    _rebind_round_copy(monkeypatch, 3, profile.README_PATH, raw)
    with pytest.raises(ValueError, match="candidate 4 is candidate 3 with only C3-1's OBS-RBAC-1 text applied"):
        profile.validate_w03_plan_amend_2()


def test_both_readmes_keep_their_candidate_status_line(monkeypatch):
    monkeypatch.setattr(profile, "CANDIDATE", "Status: **ADOPTED**")
    with pytest.raises(ValueError, match=re.escape("the README keeps its reviewed candidate status line: " + profile.README_PATH)):
        profile.validate_w03_plan_amend_2()


def test_decision_ids_are_read_as_the_records_write_them():
    assert profile.DECISION_ID.findall("Q-HE4-3/4 (a); Q-HE4A-B2 = (a); Q-HE4B-10 (a)+(c); carried G5-G7") == [
        "Q-HE4-3/4", "Q-HE4A-B2", "Q-HE4B-10"]


def _mutate_amendment(value, change):
    rows = value["changes"]
    if change == "amends_digest":
        value["amends"]["sha256"] = "sha256:" + "0" * 64
    elif change == "after_digest":
        value["after"]["sha256"] = "sha256:" + "0" * 64
    elif change == "amends_path":
        value["amends"]["path"] = "architecture/w03-plan/plan.json"
    elif change == "unknown_kind":
        rows[0]["change"] = "NARROWED"
    elif change == "extra_kind":
        value["changeKinds"]["NARROWED"] = "Ownership narrowed, as in amendment 1."
    elif change == "missing_kind":
        del value["changeKinds"]["PACKETS_ADDED"]
    elif change == "empty_decision":
        value["ownerDecisions"].append(" ")
    elif change == "uncited_decision":
        rows[0]["source"] += "; owner decision Q-HE4B-99 (a)"
    elif change == "refined_text":
        _rows(value, "I06-2")[0]["text"] += " "
    elif change == "refined_replaced":
        _rows(value, "NP-3")[0]["replaced"] = "HE-003"
    elif change == "refined_in_place":
        row = _rows(value, "SEC-4", "REFINED")[0]
        row["packets"] = [packet for packet in row["packets"] if packet != "HE-004A"] + ["HE-004A"]
    elif change == "refined_keeps_he004":
        _rows(value, "HI-7", "REFINED")[0]["packets"].append("HE-004")
    elif change == "part_unknown":
        row = _rows(value, "I06-2")[0]
        row["parts"] = row["packets"] = ["HE-004D3"]
        row["shares"] = {"HE-004D3": row["shares"]["HE-004D2"]}
    elif change == "part_uncovered":
        value["packetRefinements"][0]["parts"].append({"id": "HE-004E", "summary": "an unnamed part"})
    elif change == "refinement_other":
        value["packetRefinements"][0]["packet"] = "HE-005"
    elif change == "duplicate_refined":
        index = rows.index(_rows(value, "I06-3")[0])
        rows.insert(index + 1, copy.deepcopy(rows[index]))
    elif change == "holder_missing":
        rows.remove(_rows(value, "NP-3")[0])
    elif change == "refined_non_holder":
        row = _rows(value, "I06-2")[0]
        row["obligation"], row["text"] = "NP-1", "No production profile exists until a reviewed schema revision adds one."
    elif change == "added_plan":
        _rows(value, "I01-1")[0]["obligation"] = "NP-1"
    elif change == "added_amendment_1":
        _rows(value, "I01-1")[0]["obligation"] = "I07-6"
    elif change == "added_twice":
        rows.append(copy.deepcopy(_rows(value, "OBS-INV-1")[0]))
    elif change == "added_empty":
        _rows(value, "I05-8")[0]["packets"] = []
    elif change == "packets_added_list":
        _rows(value, "ADM-4", "PACKETS_ADDED")[0]["packets"].remove("HE-004C")
    elif change == "packets_added_present":
        row = _rows(value, "SEC-4", "PACKETS_ADDED")[0]
        row["packetsAdded"], row["packets"] = ["HE-008"], row["packets"][:-1] + ["HE-008"]
    elif change == "packets_added_he004":
        row = _rows(value, "HI-7", "PACKETS_ADDED")[0]
        row["packetsAdded"], row["packets"] = ["HE-004"], row["packets"][:-1] + ["HE-004"]
        row["shares"] = {"HE-004": row["shares"]["T04"]}
    elif change == "share_unlisted":
        _rows(value, "I06-2")[0]["shares"]["HE-008"] = "the enrolled host"
    elif change == "share_empty":
        _rows(value, "OBS-INV-1")[0]["shares"]["T04"] = ""
    else:
        raise AssertionError(change)


@pytest.mark.parametrize("change, message", [
    ("amends_digest", "the amendment binds plan v2 and amendment 1 by their bytes"),
    ("after_digest", "the amendment binds plan v2 and amendment 1 by their bytes"),
    ("amends_path", "the amendment binds plan v2 and amendment 1 by their bytes"),
    ("unknown_kind", "the closed change kinds"), ("extra_kind", "the closed change kinds"),
    ("missing_kind", "the closed change kinds"),
    ("empty_decision", "the recorded decisions are non-empty texts"),
    ("uncited_decision", "every decision a change cites is recorded"),
    ("refined_text", "keeps plan v2's text byte for byte and replaces HE-004 by its parts: I06-2"),
    ("refined_replaced", "keeps plan v2's text byte for byte and replaces HE-004 by its parts: NP-3"),
    ("refined_in_place", "keeps plan v2's text byte for byte and replaces HE-004 by its parts: SEC-4"),
    ("refined_keeps_he004", "keeps plan v2's text byte for byte and replaces HE-004 by its parts: HI-7"),
    ("part_unknown", "keeps plan v2's text byte for byte and replaces HE-004 by its parts: I06-2"),
    ("part_uncovered", "the REFINED rows' parts are exactly HE-004's parts"),
    ("refinement_other", "HE-004 is the one refined packet, with named parts"),
    ("duplicate_refined", "a REFINED row is the first row of an HE-004 obligation"),
    ("holder_missing", "every obligation that lists HE-004 after amendment 1 has exactly one REFINED row"),
    ("refined_non_holder", "a REFINED row is the first row of an HE-004 obligation"),
    ("added_plan", "an ADDED row adds an obligation absent from plan v2 and amendment 1: NP-1"),
    ("added_amendment_1", "an ADDED row adds an obligation absent from plan v2 and amendment 1: I07-6"),
    ("added_twice", "an ADDED row adds an obligation absent from plan v2 and amendment 1: OBS-INV-1"),
    ("added_empty", "an ADDED row adds an obligation absent from plan v2 and amendment 1: I05-8"),
    ("packets_added_list", "a PACKETS_ADDED row extends the obligation's list so far: ADM-4"),
    ("packets_added_present", "a PACKETS_ADDED row extends the obligation's list so far: SEC-4"),
    ("packets_added_he004", "no row keeps HE-004: HI-7"),
    ("share_unlisted", "every share names a packet in its row's list: I06-2"),
    ("share_empty", "every share names a packet in its row's list: OBS-INV-1")])
def test_every_amendment_rule_is_checked(monkeypatch, change, message):
    value = _load(profile.AMENDMENT)
    _mutate_amendment(value, change)
    _rebind(monkeypatch, {profile.AMENDMENT: _dump(value)})
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.validate_amendment()


def test_the_rules_hold_over_the_adopted_amendment_and_its_inputs():
    plan, record = _load(profile.PLAN_V2), _load(profile.AMENDMENT)
    refined = [row["obligation"] for row in record["changes"] if row["change"] == "REFINED"]
    assert sorted(refined) == ["ADM-4", "HI-7", "I06-2", "I06-3", "NP-3", "SEC-4"]
    texts = {row["id"]: row["text"] for row in plan["obligations"]}
    assert all(row["text"] == texts[row["obligation"]] for row in record["changes"] if row["change"] == "REFINED")
    assert {part for row in record["changes"] if row["change"] == "REFINED" for part in row["parts"]} == {
        "HE-004A", "HE-004B1", "HE-004C", "HE-004D1", "HE-004D2"}
    assert [row["obligation"] for row in record["changes"] if row["change"] == "ADDED"] == [
        "I01-1", "OBS-RBAC-1", "OBS-INV-1", "I05-7", "I05-8"]
    assert profile.validate_amendment() is None and profile.validate_edge_record_v4() is None


def _mutate_edge(value, change):
    rows = value["artifacts"]
    if change == "v3_row_changed":
        rows[0]["mode"] = "100644" if rows[0]["mode"] == "100755" else "100755"
    elif change == "v3_rows_reordered":
        rows[0], rows[1] = rows[1], rows[0]
    elif change == "v3_row_dropped":
        del rows[5]
    elif change == "v3_row_key_order":
        rows[2] = dict(reversed(list(rows[2].items())))
    elif change == "extra_row":
        rows.append(dict(rows[-1], providerPath="architecture/i05-gate-channel-v4/status.json"))
    elif change == "new_sha":
        rows[33]["sha256"] = "0" * 64
    elif change == "new_commit":
        rows[40]["providerCommit"] = "0" * 40
    elif change == "new_mode":
        rows[44]["mode"] = "100755"
    elif change == "new_consumer":
        rows[35]["consumerPath"] = rows[35]["consumerPath"].replace("host-enforcement/contracts/", "contracts/")
    elif change == "new_status":
        rows[36]["status"] = "IN_USE"
    elif change == "new_relation":
        rows[37]["relation"] = "DERIVED"
    elif change == "new_packet":
        rows[38]["consumerPacket"] = "HE-004B1"
    elif change == "new_extra_key":
        rows[39]["providerPacket"] = "MET-ENFORCE-032"
    elif change == "supersedes_digest":
        value["supersedes"]["sha256"] = "sha256:" + "0" * 64
    elif change == "supersedes_packet":
        value["supersedes"]["packet"] = "MET-ENFORCE-028"
    elif change == "schema":
        value["schemaVersion"] = "planeon.internal.artifact-edge-registry/v3"
    elif change == "rules":
        value["rules"].append("A consumer may hold another version.")
    elif change == "decision":
        value["ownerDecisions"].append("Monitor (2026-10-16): an unrecorded decision.")
    else:
        raise AssertionError(change)


@pytest.mark.parametrize("change, message", [
    ("v3_row_changed", "edge record v4 carries v3's 33 rows exactly and in order"),
    ("v3_rows_reordered", "edge record v4 carries v3's 33 rows exactly and in order"),
    ("v3_row_dropped", "edge record v4 carries v3's 33 rows exactly and in order"),
    ("v3_row_key_order", "edge record v4 carries v3's 33 rows exactly and in order"),
    ("extra_row", "edge record v4 carries v3's 33 rows exactly and in order"),
    ("new_sha", "edge record v4 row 34 registers"), ("new_commit", "edge record v4 row 41 registers"),
    ("new_mode", "edge record v4 row 45 registers"), ("new_consumer", "edge record v4 row 36 registers"),
    ("new_status", "edge record v4 row 37 registers"), ("new_relation", "edge record v4 row 38 registers"),
    ("new_packet", "edge record v4 row 39 registers"), ("new_extra_key", "edge record v4 row 40 registers"),
    ("supersedes_digest", "edge record v4 supersedes v3 by its digest"),
    ("supersedes_packet", "edge record v4 supersedes v3 by its digest"),
    ("schema", "edge record v4 supersedes v3 by its digest"), ("rules", "edge record v4 supersedes v3 by its digest"),
    ("decision", "edge record v4 supersedes v3 by its digest")])
def test_every_edge_record_rule_is_checked(monkeypatch, change, message):
    value = _load(profile.V4_EDGE)
    _mutate_edge(value, change)
    _rebind(monkeypatch, {profile.V4_EDGE: _dump(value)})
    with pytest.raises(ValueError, match=re.escape(message)):
        profile.validate_edge_record_v4()


def test_a_changed_provider_file_is_refused(monkeypatch):
    path = profile.NEW_ROWS[0][0]
    _rebind(monkeypatch, {path: profile.reviewed_bytes(path) + b"\n"})
    with pytest.raises(ValueError, match=re.escape("edge record v4 row 34 registers its provider's exact bytes and mode "
                                                   "before use: " + path)):
        profile.validate_edge_record_v4()


@pytest.mark.parametrize("mode", [stat.S_IFREG | 0o755, stat.S_IFLNK | 0o777])
def test_a_provider_files_mode_is_its_registered_mode(monkeypatch, mode):
    path = profile.NEW_ROWS[-1][0]
    original = profile.reviewed_mode
    monkeypatch.setattr(profile, "reviewed_mode", lambda target: mode if target == path else original(target))
    with pytest.raises(ValueError, match=re.escape("edge record v4 row 45 registers")):
        profile.validate_edge_record_v4()


def test_the_new_rows_are_restated_with_their_commits():
    rows = _load(profile.V4_EDGE)["artifacts"][profile.V3_ROWS:]
    assert [(row["providerPath"], row["providerCommit"], row["consumerPath"], row["consumerPacket"]) for row in rows] == [
        tuple(row) for row in profile.NEW_ROWS]
    assert all(re.fullmatch("[0-9a-f]{40}", row[1]) and row[2].startswith(profile.CONSUMER_PREFIX) for row in profile.NEW_ROWS)
    assert [row[3] for row in profile.NEW_ROWS] == ["HE-004"] * 10 + ["HE-003A3"] * 2


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
