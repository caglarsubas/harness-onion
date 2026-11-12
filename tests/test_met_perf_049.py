"""Exact source lineage for MET-PERF-049; CHAIN-COMPACTION-002's ledger rewrite step (K = 0): the second chain checkpoint, the reader's class cache, class rule v2.4, the demoted (authored) classification and twelve workers; the head keeps the full fan-in (8 own and 97 predecessor routes, every catalog walk and round trip, the full payload loop), and the semantic check (V1, C1-C9, V4, V6) has a failing case for every refusal, each on plain data."""
import ast
import json
from copy import deepcopy
import os
import re
import stat
from pathlib import Path
from types import MappingProxyType

import pytest

from scripts import validate_met_perf_049 as profile
from scripts import validate_met_adopt_008 as a008
from scripts import validate_met_registry_001 as r001
from scripts import validate_met_verify_007 as v007
from scripts import validate_met_perf_047 as p047
from scripts import validate_authority_map as a007
from scripts import validate_met_perf_046 as v046
from scripts import validate_met_verify_006 as v006
from scripts import validate_met_sector_005 as sec5
from scripts import validate_met_perf_045 as perf45
from scripts import validate_met_sector_004 as sec4
from scripts import validate_met_verify_005 as vf5
from scripts import validate_met_sector_003 as sec3
from scripts import validate_chain_product_publish as cpp
from scripts import validate_release_profile as adopt6
from scripts import validate_edge_record_v12 as ev12
from scripts import validate_met_perf_043 as perf43
from scripts import validate_met_gov_005 as gov5
from scripts import validate_met_adopt_005 as adopt5
from scripts import validate_met_gov_004 as gov4
from scripts import validate_met_linux_008 as ml8
from scripts import validate_policy_observation_digests_v2 as pod2
from scripts import validate_met_linux_009 as ml9
from scripts import validate_linux_probe_kit_admission as lpka
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
    # The newer MET-006 layer is projected away before this layer's payload checks.
    return profile.successor.historical_catalog(packets())


def changed_test():
    return next(path for path in profile._PROJECTION_RULES if path.startswith("tests/"))


def test_exact_current_source_and_complete_history_chain():
    assert profile.validate() is None
    current = packets()
    accepted = profile.historical_catalog(current)
    assert len(current) == 300 and len(accepted) == 296
    assert set(accepted) == set(current) - {profile.NEW_PACKET, profile.successor.NEW_PACKET,
                                            profile.successor.successor.NEW_PACKET,
                                            *profile.successor.successor.PRODUCT_PACKETS}
    assert len(a008.historical_catalog(current)) == 295
    assert len(r001.historical_catalog(current)) == 293
    assert len(v007.historical_catalog(current)) == 289
    assert len(p047.historical_catalog(current)) == 288
    assert len(a007.historical_catalog(current)) == 287
    assert len(v046.historical_catalog(current)) == 286
    assert len(v006.historical_catalog(current)) == 283
    assert len(sec5.historical_catalog(current)) == 281
    assert len(perf45.historical_catalog(current)) == 280
    assert len(sec4.historical_catalog(current)) == 278
    assert len(vf5.historical_catalog(current)) == 275
    assert len(sec3.historical_catalog(current)) == 273
    assert len(cpp.historical_catalog(current)) == 272
    assert len(adopt6.historical_catalog(current)) == 271
    assert len(ev12.historical_catalog(current)) == 270
    assert len(perf43.historical_catalog(current)) == 269
    assert len(gov5.historical_catalog(current)) == 268
    assert len(adopt5.historical_catalog(current)) == 267
    assert len(gov4.historical_catalog(current)) == 266
    assert len(ml8.historical_catalog(current)) == 265
    assert len(pod2.historical_catalog(current)) == 264
    assert len(ml9.historical_catalog(current)) == 263
    assert len(lpka.historical_catalog(current)) == 262
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
    a008_before = a008.historical_bytes(path, current)
    assert a008.current_test_bytes(a008_before) == current
    r001_before = r001.historical_bytes(path, current)
    assert r001.current_test_bytes(r001_before) == current
    v007_before = v007.historical_bytes(path, current)
    assert v007.current_test_bytes(v007_before) == current
    p047_before = p047.historical_bytes(path, current)
    assert p047.current_test_bytes(p047_before) == current
    a007_before = a007.historical_bytes(path, current)
    assert a007.current_test_bytes(a007_before) == current
    v046_before = v046.historical_bytes(path, current)
    assert v046.current_test_bytes(v046_before) == current
    v006_before = v006.historical_bytes(path, current)
    assert v006.current_test_bytes(v006_before) == current
    sec5_before = sec5.historical_bytes(path, current)
    assert sec5.current_test_bytes(sec5_before) == current
    perf45_before = perf45.historical_bytes(path, current)
    assert perf45.current_test_bytes(perf45_before) == current
    sec4_before = sec4.historical_bytes(path, current)
    assert sec4.current_test_bytes(sec4_before) == current
    vf5_before = vf5.historical_bytes(path, current)
    assert vf5.current_test_bytes(vf5_before) == current
    sec3_before = sec3.historical_bytes(path, current)
    assert sec3.current_test_bytes(sec3_before) == current
    cpp_before = cpp.historical_bytes(path, current)
    assert cpp.current_test_bytes(cpp_before) == current
    adopt6_before = adopt6.historical_bytes(path, current)
    assert adopt6.current_test_bytes(adopt6_before) == current
    ev12_before = ev12.historical_bytes(path, current)
    assert ev12.current_test_bytes(ev12_before) == current
    perf43_before = perf43.historical_bytes(path, current)
    assert perf43.current_test_bytes(perf43_before) == current
    gov5_before = gov5.historical_bytes(path, current)
    assert gov5.current_test_bytes(gov5_before) == current
    adopt5_before = adopt5.historical_bytes(path, current)
    assert adopt5.current_test_bytes(adopt5_before) == current
    gov4_before = gov4.historical_bytes(path, current)
    assert gov4.current_test_bytes(gov4_before) == current
    ml8_before = ml8.historical_bytes(path, current)
    assert ml8.current_test_bytes(ml8_before) == current
    pod2_before = pod2.historical_bytes(path, current)
    assert pod2.current_test_bytes(pod2_before) == current
    ml9_before = ml9.historical_bytes(path, current)
    assert ml9.current_test_bytes(ml9_before) == current
    lpka_before = lpka.historical_bytes(path, current)
    assert lpka.current_test_bytes(lpka_before) == current
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


@pytest.mark.parametrize("route", ["authority", "changed", "old_bytes", "unchanged", "historical_test", "current_test", "catalog", "payloads", "a008_old"])
def test_newest_authority_is_freshly_checked_on_every_route(monkeypatch, route):
    path = changed_test()
    raw = profile.regular_bytes(path)
    before = profile.historical_bytes(path, raw) if route in ("current_test", "old_bytes") else None
    current_packets = packets() if route == "catalog" else None
    layer = layer_packets() if route == "payloads" else None
    master_raw = roadmap.regular_bytes(roadmap.MASTER_PATH)
    old_a008 = a008.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "a008_old" else None
    old_r001 = r001.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "r001_old" else None
    old_v007 = v007.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "v007_old" else None
    old_p047 = p047.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "p047_old" else None
    old_a007 = a007.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "a007_old" else None
    old_v046 = v046.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "v046_old" else None
    old_v006 = v006.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "v006_old" else None
    old_sec5 = sec5.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "sec5_old" else None
    old_perf45 = perf45.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "perf45_old" else None
    old_sec4 = sec4.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "sec4_old" else None
    old_vf5 = vf5.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "vf5_old" else None
    old_sec3 = sec3.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "sec3_old" else None
    old_cpp = cpp.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "cpp_old" else None
    old_adopt6 = adopt6.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "adopt6_old" else None
    old_ev12 = ev12.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "ev12_old" else None
    old_perf43 = perf43.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "perf43_old" else None
    old_gov5 = gov5.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "gov5_old" else None
    old_adopt5 = adopt5.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "adopt5_old" else None
    old_gov4 = gov4.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "gov4_old" else None
    old_ml8 = ml8.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "ml8_old" else None
    old_pod2 = pod2.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "pod2_old" else None
    old_ml9 = ml9.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "ml9_old" else None
    old_lpka = lpka.historical_bytes(roadmap.MASTER_PATH, master_raw) if route == "lpka_old" else None
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
        "a008_old": lambda: a008.historical_bytes(roadmap.MASTER_PATH, old_a008),
        "r001_old": lambda: r001.historical_bytes(roadmap.MASTER_PATH, old_r001),
        "v007_old": lambda: v007.historical_bytes(roadmap.MASTER_PATH, old_v007),
        "p047_old": lambda: p047.historical_bytes(roadmap.MASTER_PATH, old_p047),
        "a007_old": lambda: a007.historical_bytes(roadmap.MASTER_PATH, old_a007),
        "v046_old": lambda: v046.historical_bytes(roadmap.MASTER_PATH, old_v046),
        "v006_old": lambda: v006.historical_bytes(roadmap.MASTER_PATH, old_v006),
        "sec5_old": lambda: sec5.historical_bytes(roadmap.MASTER_PATH, old_sec5),
        "perf45_old": lambda: perf45.historical_bytes(roadmap.MASTER_PATH, old_perf45),
        "sec4_old": lambda: sec4.historical_bytes(roadmap.MASTER_PATH, old_sec4),
        "vf5_old": lambda: vf5.historical_bytes(roadmap.MASTER_PATH, old_vf5),
        "sec3_old": lambda: sec3.historical_bytes(roadmap.MASTER_PATH, old_sec3),
        "cpp_old": lambda: cpp.historical_bytes(roadmap.MASTER_PATH, old_cpp),
        "adopt6_old": lambda: adopt6.historical_bytes(roadmap.MASTER_PATH, old_adopt6),
        "ev12_old": lambda: ev12.historical_bytes(roadmap.MASTER_PATH, old_ev12),
        "perf43_old": lambda: perf43.historical_bytes(roadmap.MASTER_PATH, old_perf43),
        "gov5_old": lambda: gov5.historical_bytes(roadmap.MASTER_PATH, old_gov5),
        "adopt5_old": lambda: adopt5.historical_bytes(roadmap.MASTER_PATH, old_adopt5),
        "gov4_old": lambda: gov4.historical_bytes(roadmap.MASTER_PATH, old_gov4),
        "ml8_old": lambda: ml8.historical_bytes(roadmap.MASTER_PATH, old_ml8),
        "pod2_old": lambda: pod2.historical_bytes(roadmap.MASTER_PATH, old_pod2),
        "ml9_old": lambda: ml9.historical_bytes(roadmap.MASTER_PATH, old_ml9),
        "lpka_old": lambda: lpka.historical_bytes(roadmap.MASTER_PATH, old_lpka),
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
    with pytest.raises(ValueError, match="ledger rewrite history authority digest"):
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
    assert len(profile.historical_catalog(current)) == 296


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
    assert len(profile.historical_catalog(current)) == 296
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
    assert len(rules) == 297 and len(parsed) == 296
    assert profile._packet_rules() is rules and len(parsed) == 296
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
    with pytest.raises(ValueError, match="ledger rewrite history authority digest"):
        profile.validate_packet_payloads(current)


def test_cached_expected_rules_are_bound_to_source_root(tmp_path, monkeypatch):
    current = layer_packets()
    profile.validate_packet_payloads(current)
    authority_dir = tmp_path / "architecture"
    authority_dir.mkdir()
    (authority_dir / "ledger-rewrite-authority.json").write_bytes(
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
    # The newer MET-006 layer refuses a mutated validator before this layer.
    with pytest.raises(ValueError, match="unreviewed current source: scripts/validate_met_perf_049.py"):
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
            assert all("validate_" not in alias.name or alias.name == "validate_met_006"
                       for alias in node.names)


def _count_authority_reads(monkeypatch):
    counts = {}
    for module in (profile.successor, profile, a008, r001, v007, p047, a007, v046, v006, sec5, perf45, sec4, vf5, sec3, cpp, adopt6, ev12, perf43, gov5, adopt5, gov4, ml8, pod2, ml9, lpka, lpi, lkg, pks, rrv, pod, evs, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner):
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
    expected = {module.__name__: 1 for module in (profile.successor, profile, a008, r001, v007, p047, a007, v046, v006, sec5, perf45, sec4, vf5, sec3, cpp, adopt6, ev12, perf43, gov5, adopt5, gov4, ml8, pod2, ml9, lpka, lpi, lkg, pks, rrv, pod, evs, e9, ccomp, i6v4, dcap, np5, lrp, wpa3, cfp3, sol, mx6, np4, tcv1, wpa2, la2, i5v4, cdh, cfp2, smx, phr, sv4, hs43, rav3, deadlines, events, filters, loop, manifest, ledger, adoption, amendment, bprofile, mprofile, eprofile, lprofile, fprofile, oprofile, uprofile, jprofile, kprofile, tprofile, zprofile, yprofile, xprofile, pprofile, aprofile, vprofile, cprofile, qprofile, hprofile, dprofile, sprofile, wprofile, rprofile, gprofile, iprofile, nprofile, resolution, account, canary, isolated, portable, proof, recheck, verifier, linux, performance, runner)}
    if route == "current_test":
        # The forward route reads this layer's newest bytes and then projects them forward once more.
        assert all(counts[name] >= 1 for name in expected) and set(counts) == set(expected)
    else:
        assert counts == expected


# MET-PERF-049 (CHAIN-COMPACTION-002's ledger rewrite step): this era's check, and a failing case for every check (K = 0).
# Every mutant below is applied to plain data handed to the layer's pure checks: nothing in the layer, the reader or the
# library is patched or swapped. The ledger checks (C1, C2) run on a synthetic ledger and inline entry built here, and
# on the live ones once the writing run's ledger is in the tree.
import base64 as _b64

VALIDATE = profile.validate_met_perf_049
OWN_PATH = "task-packets/MET-PERF-049.yaml"
V_TESTS = {
    "V1": ("test_v1_every_era_file_is_bound_by_its_digest", "test_v1_the_packet_files_are_exactly_the_ten"),
    "C1": ("test_c1_the_ledger_rechecks_in_full",),
    "C2": ("test_c2_the_inline_entry_rechecks_in_full", "test_c2_the_canonical_check_skips_only_the_ledger",
           "test_c2_the_live_entry_projects_slot_282s_record"),
    "C3": ("test_c3_the_reader_rechecks_in_full",),
    "C4": ("test_c4_the_rule_copy_rechecks_in_full",),
    "C5": ("test_c5_the_once_flag_rechecks_in_full",),
    "C6": ("test_c6_the_provisions_recheck_in_full",),
    "C7": ("test_c7_the_workers_recheck_in_full",),
    "C8": ("test_c8_the_bridged_layer_rechecks",),
    "C9": ("test_c9_the_demotion_rechecks_in_full",),
    "V4": ("test_v4_the_registry_differs_from_the_base_by_the_one_rider",),
    "V6": ("test_v6_the_hunk_class_record_rechecks_in_full", "test_v6_the_ledger_classes_are_one_other_per_hunk"),
}
V1_BOUND = "MET-PERF-049 reviewed bytes are bound: "
V1_DRIFT = "unreviewed MET-PERF-049 source: "
V1_FILES = "MET-PERF-049 V1 the packet files are exactly the ten"
V1_FILE = "MET-PERF-049 V1 a packet file's bytes equal its pinned digest: "
C1_NAMED = "MET-PERF-049 C1 the ledger is named by this step's authority over slot 282's record"
C1_CLOSED = "MET-PERF-049 C1 the ledger is the closed slot-286 checkpoint over the 296-packet baseline"
C1_PARAMS = "MET-PERF-049 C1 the ledger's parameters are the owner's numbers"
C1_PROOF = "MET-PERF-049 C1 the ledger's full-run proof: every collected node executed"
C1_RUN = "MET-PERF-049 C1 the writing run states both differences, the capture variables and the verify reference"
C1_PAIRS = "MET-PERF-049 C1 the ledger's check pairs are ruled supersessions"
C1_SIZE = "MET-PERF-049 C1 the ledger's size is its length, within its bound, within 16 MiB"
C1_LAYERS = "MET-PERF-049 C1 the ledger's layers have their closed members"
C1_EXCL = "MET-PERF-049 C1 the ledger's exclusion is this step's write set, and no layer attests an excluded file"
C1_WALK = "MET-PERF-049 C1 the ledger's layers are the chain walk 189-285"
C1_BIND = "MET-PERF-049 C1 the chain walk: slot "
C2_ENTRY = "MET-PERF-049 C2 the record.json entry is the plain three-key form over slot 282's record"
C2_REPLAY = "MET-PERF-049 C2 the record.json entry's reverse hunks reproduce slot 282's record"
C3_CACHE = "MET-PERF-049 C3 the reader's L1 and L2 caches"
C3_RULES = "MET-PERF-049 C3 RULES_BY_SHA holds the v2.2, v2.3 and v2.4 digests"
C3_TABLE = "MET-PERF-049 C3 COUNT_EFFECT equals the README's table"
C4 = "MET-PERF-049 C4 the reader's v2.4 rule copy is the pinned tool"
C5 = "MET-PERF-049 C5 tests/conftest.py's once-per-process flag, and nothing else"
C6 = "MET-PERF-049 C6 MET-PERF-048's provisions are present and inert"
C7_ONCE = "MET-PERF-049 C7 WORKERS is 12, once"
C7_FOLLOW = "MET-PERF-049 C7 the pin, the README, the page and the writer follow WORKERS"
C8 = "MET-PERF-049 C8 285's layer reads through this step's projection"
C9 = "MET-PERF-049 C9 the demotion's kinds and record fields"
V4_MESSAGE = "the registry differs from the base by exactly the MET-PERF-049 packet rider"
V6_CLOSED = "MET-PERF-049 V6 the hunk-class record is closed and names this layer's authority"
V6_PINNED = "MET-PERF-049 V6 the hunk-class record's vocabulary and rule digest are v2.4's"
V6_CONTEXT = "MET-PERF-049 V6 the hunk-class record's context is this step's names"
V6_COVER = "MET-PERF-049 V6 the hunk-class record lists one class per hunk for exactly the changed files"
V6_RECHECK = "MET-PERF-049 V6 a recorded class re-checks by position: "
V6_LEDGER = "MET-PERF-049 V6 record.json's classes are exactly one other per hunk"
READER = "ci/chain_checkpoint.py"


def _chain_packets():
    """The live packets, read as validate() reads them (each file's bytes through the layer, parsed by safe_load)."""
    return {path.stem: profile.safe_load(profile.regular_bytes("task-packets/" + path.name))
            for path in sorted((profile.ROOT / "task-packets").glob("*.yaml"))}


def _sha(raw):
    import hashlib
    return hashlib.sha256(raw).hexdigest()


def _raises(message, call):
    with pytest.raises(ValueError, match=re.escape(message)):
        call()


def test_every_check_has_a_test_that_makes_it_fail():
    names = {name for name, value in globals().items() if name.startswith("test_") and callable(value)}
    assert sorted(V_TESTS) == ["C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "V1", "V4", "V6"]
    assert all(test in names for tests in V_TESTS.values() for test in tests)


def test_the_contract_holds_for_this_era():
    assert VALIDATE(_chain_packets()) is None


def test_the_era_holds_the_packet_files_the_registry_and_the_brief():
    assert not hasattr(profile, "PRODUCT_PACKETS")
    assert len(profile.PACKET_FILES) == 10 and len(profile.ERA_SHA256) == 12
    assert set(profile.PACKET_FILES) | {profile.REGISTRY_PATH, profile.PACKET_BRIEF} == set(profile.ERA_SHA256)
    for path, expected in profile.ERA_SHA256.items():
        assert _sha(profile.reviewed_bytes(path)) == expected
    record = profile.authority()
    assert sorted(record) == ["acceptedBase", "authorityPacket", "baselinePackets", "changedFiles", "newFiles",
                              "packetSha256", "schemaVersion", "validatorNormalizedSha256"]
    assert len(record["baselinePackets"]) == 296
    assert profile.HUNK_RECORD_PATH in record["newFiles"] and profile.HUNK_RECORD_PATH not in profile.ERA_SHA256
    assert profile.LEDGER_PATH not in profile.ERA_SHA256 and profile.SIDE_PATH not in profile.ERA_SHA256
    assert set(profile.PACKET_FILES) <= set(record["changedFiles"])
    assert profile.VALIDATOR_PATH not in record["newFiles"] and OWN_PATH not in record["newFiles"]


@pytest.mark.parametrize("change", ["outside_path", "outside_read", "not_a_string", "byte_appended", "crlf", "not_bytes"])
def test_v1_every_era_file_is_bound_by_its_digest(change):
    for path in profile.ERA_SHA256:
        raw = profile._verified(path)
        assert profile._era_bytes(path, raw) is raw
    raw = profile._verified(READER)
    outside = "ci/verify-offline.sh"
    mutants = {
        "outside_path": (lambda: profile._era_bytes(outside, raw), V1_BOUND + outside),
        "outside_read": (lambda: profile._verified(outside), V1_BOUND + outside),
        "not_a_string": (lambda: profile._era_bytes(Path(READER), raw), V1_BOUND),
        "byte_appended": (lambda: profile._era_bytes(READER, raw + b"\n"), V1_DRIFT + READER),
        "crlf": (lambda: profile._era_bytes(READER, raw.replace(b"\n", b"\r\n", 1)), V1_DRIFT + READER),
        "not_bytes": (lambda: profile._era_bytes(READER, raw.decode("utf-8")), V1_DRIFT + READER),
    }
    call, message = mutants[change]
    _raises(message, call)


@pytest.mark.parametrize("change", ["missing", "extra", "byte"])
def test_v1_the_packet_files_are_exactly_the_ten(change):
    files = {path: profile._verified(path) for path in profile.PACKET_FILES}
    assert profile.check_packet_files(files) is None
    if change == "missing":
        files.pop(READER)
        message = V1_FILES
    elif change == "extra":
        files["ci/other.py"] = b""
        message = V1_FILES
    else:
        files[READER] = files[READER] + b" "
        message = V1_FILE + READER
    _raises(message, lambda: profile.check_packet_files(files))


# C1 on a synthetic ledger: 97 layers 189-285, each validator binding the next; the entry names it over 282's record.
def _ledger_doc():
    modules = ["validate_unified_roadmap"] + ["validate_l%d" % slot for slot in range(190, 285)] + ["validate_met_adopt_008"]
    layers = [{"slot": 189 + i, "module": m, "validatorPath": "scripts/%s.py" % m, "validatorSha256": "a" * 64,
               "authorityPath": "architecture/l%d-authority.json" % (189 + i), "authoritySha256": "b" * 64,
               "inputs": {"data/%d.txt" % (189 + i): "c" * 64}, "nodes": [], "seconds": 1.0} for i, m in enumerate(modules)]
    names = modules + ["validate_met_perf_049"]
    walk = {layer["validatorPath"]: ((" %s import x\n" % names[i + 1]) if i == 0 else
                                     ("import %s as successor\n" % names[i + 1])).encode() for i, layer in enumerate(layers)}
    doc = {"schemaVersion": profile.LEDGER_SCHEMA, "checkpointSlot": 286, "checkpointBaseline": 296,
           "writingCommit": "d" * 40, "writingTree": "e" * 40,
           "parameters": dict(profile.PARAMETERS, shadowIn="verify"), "normalisedRecordClass": True, "layers": layers,
           "checkPairs": [{"layerSlot": 270, "pairsPath": "architecture/p.json", "ids": ["A-1", "A-2"], "type": "supersession"}],
           "fullRunProof": {"collected": 10, "executed": 10, "deselected": 0, "attested": 0},
           "writingRun": {"statedDifferences": list(profile.STATED), "captureEnv": list(profile.CAPTURE_ENV),
                          "captureObservesOnly": True, "outsideReads": 3, "argvRunSummarySha256": "f" * 64,
                          "verifyReference": profile.VERIFY_REFERENCE},
           "exclusion": {"files": list(profile.EXCLUSION_FILES), "pinLine": profile.VALIDATOR_PATH},
           "sizeBound": 12_000_000, "sizeBytes": 0}
    return doc, walk


def _ledger_raw(doc):
    for _ in range(5):
        raw = (json.dumps(doc, sort_keys=True, indent=1) + "\n").encode()
        if doc["sizeBytes"] == len(raw):
            return raw
        doc["sizeBytes"] = len(raw)
    return raw


def _entry(raw):
    return {"beforeSha256": profile.PREVIOUS_CHECKPOINT[1], "afterSha256": _sha(raw),
            "reverseHunks": [{"at": 0, "removeBase64": "YQ==", "insertBase64": "Yg=="}]}


@pytest.mark.parametrize("change", ["entry_keys", "entry_before", "entry_digest", "member", "slot", "baseline", "workers",
                                    "shadow_in", "proof", "stated", "reference", "pairs", "size_cap", "size_bytes",
                                    "layer_member", "exclusion", "attests_excluded", "walk_gap", "walk_bind"])
def test_c1_the_ledger_rechecks_in_full(change):
    doc, walk = _ledger_doc()
    raw = _ledger_raw(doc)
    assert profile.check_ledger(raw, walk, 296, _entry(raw)) is None
    entry, baseline, message = None, 296, None
    if change == "entry_keys":
        entry, message = dict(_entry(raw), extra=1), C1_NAMED
    elif change == "entry_before":
        entry, message = dict(_entry(raw), beforeSha256="0" * 64), C1_NAMED
    elif change == "entry_digest":
        entry, message = dict(_entry(raw), afterSha256="0" * 64), C1_NAMED
    elif change == "member":
        doc["extra"], message = 1, C1_CLOSED
    elif change == "slot":
        doc["checkpointSlot"], message = 282, C1_CLOSED
    elif change == "baseline":
        baseline, message = 295, C1_CLOSED
    elif change == "workers":
        doc["parameters"]["workers"], message = 8, C1_PARAMS
    elif change == "shadow_in":
        doc["parameters"]["shadowIn"], message = "always", C1_PARAMS
    elif change == "proof":
        doc["fullRunProof"]["deselected"], message = 1, C1_PROOF
    elif change == "stated":
        doc["writingRun"]["statedDifferences"][1] = doc["writingRun"]["statedDifferences"][1].replace("12", "8")
        message = C1_RUN
    elif change == "reference":
        doc["writingRun"]["verifyReference"], message = "none: the first checkpoint records the writing run itself", C1_RUN
    elif change == "pairs":
        doc["checkPairs"][0]["type"], message = "replacement", C1_PAIRS
    elif change == "size_cap":
        doc["sizeBound"], message = 17_000_000, C1_SIZE
    elif change == "size_bytes":
        doc["sizeBytes"] += 1
        message = C1_SIZE
    elif change == "layer_member":
        doc["layers"][5].pop("seconds")
        message = C1_LAYERS
    elif change == "exclusion":
        doc["exclusion"]["files"], message = doc["exclusion"]["files"][1:], C1_EXCL
    elif change == "attests_excluded":
        doc["layers"][3]["inputs"][profile.LEDGER_PATH], message = "c" * 64, C1_EXCL
    elif change == "walk_gap":
        doc["layers"].pop(40)
        message = C1_WALK
    else:
        walk[doc["layers"][50]["validatorPath"]], message = b"no successor here\n", C1_BIND + "239 binds its successor"
    if not change.startswith("entry"):
        raw = ((json.dumps(doc, sort_keys=True, indent=1) + "\n").encode() if change == "size_bytes" else _ledger_raw(doc))
        entry = _entry(raw)
    _raises(message, lambda: profile.check_ledger(raw, walk, baseline, entry))


def _base_ledger():
    """Slot 282's record: the live ledger before the writing run, or the live one undone by its inline entry after it."""
    raw = profile.reviewed_bytes(profile.LEDGER_PATH)
    if _sha(raw) == profile.PREVIOUS_CHECKPOINT[1]:
        return raw
    entry = profile.authority()["changedFiles"][profile.LEDGER_PATH]
    chunks, cursor = [], 0          # one ascending pass
    for hunk in sorted(entry["reverseHunks"], key=lambda h: h["at"]):
        remove, insert = _b64.b64decode(hunk["removeBase64"]), _b64.b64decode(hunk["insertBase64"])
        chunks.extend((raw[cursor:hunk["at"]], insert))
        cursor = hunk["at"] + len(remove)
    return b"".join(chunks) + raw[cursor:]


def _inline_case():
    """A synthetic live ledger (282's record with its slot line changed) and its one-hunk inline entry, built directly."""
    base = _base_ledger()
    old_line = b'"checkpointSlot": 282'
    at = base.index(old_line)
    start = base.rindex(b"\n", 0, at) + 1
    end = base.index(b"\n", at) + 1
    live = base[:start] + base[start:end].replace(old_line, b'"checkpointSlot": 286') + base[end:]
    hunks = [{"at": start, "removeBase64": _b64.b64encode(live[start:end]).decode(),
              "insertBase64": _b64.b64encode(base[start:end]).decode()}]
    return {"beforeSha256": _sha(base), "afterSha256": _sha(live), "reverseHunks": hunks}, live


@pytest.mark.parametrize("change", ["entry_extra", "entry_missing", "entry_before", "entry_after", "hunks_empty",
                                    "hunk_misses", "hunk_key", "hunk_overlap", "live_other"])
def test_c2_the_inline_entry_rechecks_in_full(change):
    entry, live = _inline_case()
    assert profile.check_inline(entry, live) is None
    message = C2_ENTRY
    if change == "entry_extra":
        entry["reverseHunksRecord"] = {"path": profile.SIDE_PATH, "sha256": "9" * 64}
    elif change == "entry_missing":
        del entry["beforeSha256"]
    elif change == "entry_before":
        entry["beforeSha256"] = "0" * 64
    elif change == "entry_after":
        entry["afterSha256"] = "0" * 64
    elif change == "hunks_empty":
        entry["reverseHunks"] = []
    elif change == "hunk_misses":
        entry["reverseHunks"][0]["at"] += 1
        message = C2_REPLAY
    elif change == "hunk_key":
        entry["reverseHunks"][0]["class"] = "record"
        message = C2_REPLAY
    elif change == "hunk_overlap":
        entry["reverseHunks"].append(dict(entry["reverseHunks"][0]))
        message = C2_REPLAY
    else:
        live = live + b"\n"
    _raises(message, lambda: profile.check_inline(entry, live))


def test_c2_the_canonical_check_skips_only_the_ledger(monkeypatch):
    """Q-PERF40-4's canonical check runs for every projected path except record.json (C2 replays its line-run hunks)."""
    seen = []
    monkeypatch.setattr(profile, "check_canonical_hunks", lambda path, rule, after: seen.append(path))
    profile.validate_canonical_hunks()
    assert sorted(seen) == sorted(set(profile._PROJECTION_RULES) - {profile.LEDGER_PATH}) and len(seen) == len(set(seen))


def test_c2_the_live_entry_projects_slot_282s_record():
    """At the writing run's ledger, the frozen projection of record.json is slot 282's record byte for byte."""
    entry = profile.authority()["changedFiles"].get(profile.LEDGER_PATH)
    if entry is None:
        return
    rule = profile._PROJECTION_RULES[profile.LEDGER_PATH]
    raw = profile.regular_bytes(profile.LEDGER_PATH)
    before = profile.historical_bytes(profile.LEDGER_PATH, raw)
    assert profile.digest(raw) == rule["afterSha256"] == entry["afterSha256"]
    assert profile.digest(before) == rule["beforeSha256"] == profile.PREVIOUS_CHECKPOINT[1]


@pytest.mark.parametrize("change", ["no_classes_keyword", "no_l2_fill", "rule_digest", "rules_key", "table_row",
                                    "table_extra"])
def test_c3_the_reader_rechecks_in_full(change):
    reader, readme = profile._verified(READER), profile._verified(profile.README_PATH)
    assert profile.check_reader(reader, readme) is None
    if change == "no_classes_keyword":
        reader, message = reader.replace(b"def rebuild(path, live, newer, norm, budget=None, classes=None):",
                                         b"def rebuild(path, live, newer, norm, budget=None):", 1), C3_CACHE
    elif change == "no_l2_fill":
        reader, message = reader.replace(b"self._l2[key] = value", b"self._l2.clear()", 1), C3_CACHE
    elif change == "rule_digest":
        reader, message = reader.replace(b'RULE_V24_SHA256 = "8c61', b'RULE_V24_SHA256 = "0c61', 1), C3_RULES
    elif change == "rules_key":
        reader, message = reader.replace(b"                RULE_V24_SHA256: (CLASSES, True)}", b"}", 1), C3_RULES
    elif change == "table_row":
        readme, message = readme.replace(b"| demoted | \xe2\x80\x94 | neutral |", b"| demoted | A | neutral |", 1), C3_TABLE
    else:
        readme, message = readme + b"\n| extra | C | neutral | a row the reader lacks |\n", C3_TABLE
    _raises(message, lambda: profile.check_reader(reader, readme))


@pytest.mark.parametrize("change", ["block_byte", "context_keys", "side_members", "end_mark"])
def test_c4_the_rule_copy_rechecks_in_full(change):
    reader = profile._verified(READER)
    assert profile.check_rule(reader) is None
    at = reader.index(profile.V24_MARKS[0]) + 200
    reader = {"block_byte": reader[:at] + bytes([reader[at] ^ 1]) + reader[at + 1:],
              "context_keys": reader.replace(profile.V24_LINES[0], b'CONTEXT_KEYS_V24 = CONTEXT_KEYS\n', 1),
              "side_members": reader.replace(profile.V24_LINES[1], b"SIDE_MEMBERS_V24 = SIDE_MEMBERS", 1),
              "end_mark": reader.replace(profile.V24_MARKS[1], b"# ---- end ----\n", 1)}[change]
    _raises(C4, lambda: profile.check_rule(reader))


@pytest.mark.parametrize("change", ["no_flag", "flag_early", "limit_changed", "flag_twice"])
def test_c5_the_once_flag_rechecks_in_full(change):
    raw = profile._verified(profile.TESTS_CONFTEST)
    assert profile.check_tests_conftest(raw) is None
    if change == "no_flag":
        raw = raw.replace(b"            gc.freeze()\n            _CHAIN_PRELOADED = True\n", b"            gc.freeze()\n", 1)
    elif change == "flag_early":
        raw = raw.replace(b"            gc.freeze()\n            _CHAIN_PRELOADED = True\n",
                          b"            _CHAIN_PRELOADED = True\n            gc.freeze()\n", 1)
    elif change == "limit_changed":
        raw = raw.replace(b"sys.setrecursionlimit(", b"sys.setrecursionlimit(1 + ", 1)
    else:
        raw = raw + b"\n_CHAIN_PRELOADED = False\n"
    _raises(C5, lambda: profile.check_tests_conftest(raw))


@pytest.mark.parametrize("change", ["g1_present", "signal_max", "no_link_refusal", "writer_refusal", "no_select_guard",
                                    "conftest_other"])
def test_c6_the_provisions_recheck_in_full(change):
    reader, writer = profile._verified(READER), profile._verified(profile.WRITER_PATH)
    conftest = profile._verified(profile.CONFTEST_PATH)
    assert profile.check_provisions(reader, writer, conftest, False) is None
    present = False
    if change == "g1_present":
        present = True
    elif change == "signal_max":
        reader = reader.replace(b"SIGNAL_MAX = 4096\n", b"SIGNAL_MAX = 65536\n", 1)
    elif change == "no_link_refusal":
        reader = reader.replace(b"os.O_NOFOLLOW", b"0")
    elif change == "writer_refusal":
        writer = writer.replace(b"if signal_present(", b"if not_signal_present(")
    elif change == "no_select_guard":
        conftest = conftest.replace(b'getattr(reader, "select", None)', b"reader.select", 1)
    else:
        conftest = conftest + b"\n# an unreviewed line\n"
    _raises(C6, lambda: profile.check_provisions(reader, writer, conftest, present))


@pytest.mark.parametrize("change", ["eight", "float", "twice", "pin", "readme", "page", "writer_literal"])
def test_c7_the_workers_recheck_in_full(change):
    suite = profile._verified(profile.SUITE_PATH)
    texts = {path: profile._verified(path) for path in profile.C7_LINES}
    assert profile.check_workers(suite, texts) is None
    message = C7_FOLLOW
    if change == "eight":
        suite, message = suite.replace(b"\nWORKERS = 12\n", b"\nWORKERS = 8\n", 1), C7_ONCE
    elif change == "float":
        suite, message = suite.replace(b"\nWORKERS = 12\n", b"\nWORKERS = 12.0\n", 1), C7_ONCE
    elif change == "twice":
        suite, message = suite.replace(b"\nWORKERS = 12\n", b"\nWORKERS = 12\nWORKERS = 12\n", 1), C7_ONCE
    elif change == "pin":
        texts[profile.SUITE_TEST] = texts[profile.SUITE_TEST].replace(b"WORKERS == 12\n", b"WORKERS == 8\n", 1)
    elif change == "readme":
        texts[profile.README_PATH] = texts[profile.README_PATH].replace(b"runs 12 workers.", b"runs 8 workers.", 1)
    elif change == "page":
        texts[profile.PAGE_PATH] = texts[profile.PAGE_PATH].replace(b"to 12 worker processes", b"to 8 worker processes", 1)
    else:
        texts[profile.WRITER_PATH] = texts[profile.WRITER_PATH].replace(b'the verify runs %d workers" % workers',
                                                                        b'the verify runs 12 workers"', 1)
    _raises(message, lambda: profile.check_workers(suite, texts))


def test_c8_the_bridged_layer_rechecks():
    raw = profile._bound_read(profile.BRIDGED_LAYER, profile.authority()["changedFiles"][profile.BRIDGED_LAYER]["afterSha256"])
    assert profile.check_bridged(raw) is None
    for live in (raw.replace(profile.C8_FORM, b"    result = model.check(regular_bytes, frozenset(packets))\n", 1),
                 raw.replace(profile.C8_READ, b"    return regular_bytes(path)\n", 1)):
        _raises(C8, lambda: profile.check_bridged(live))


@pytest.mark.parametrize("change", ["row", "fraction", "fields", "demoted_kind"])
def test_c9_the_demotion_rechecks_in_full(change):
    reader = profile._verified(READER)
    assert profile.check_demotion(reader) is None
    reader = {"row": reader.replace(profile.C9_READER[0], b"}", 1),
              "fraction": reader.replace(profile.C9_READER[1], b'"fraction": ', 1),
              "fields": reader.replace(profile.C9_READER[2], b'"isolation": self.isolation}', 1),
              "demoted_kind": reader.replace(profile.C9_READER[3], b'kind="demoted", countEffect="neutral")', 1)}[change]
    _raises(C9, lambda: profile.check_demotion(reader))


@pytest.mark.parametrize("change", ["no_rider", "second_rider", "rider_not_last", "brief_byte", "other_entry",
                                    "renamed_series"])
def test_v4_the_registry_differs_from_the_base_by_the_one_rider(change):
    raw = profile._verified(profile.REGISTRY_PATH)
    briefs = {profile.PACKET_BRIEF: profile._verified(profile.PACKET_BRIEF)}
    assert profile.check_registry(raw, briefs) is None
    registry = json.loads(raw)
    rider = registry["briefs"][-1]
    if change == "no_rider":
        registry["briefs"] = registry["briefs"][:-1]
    elif change == "second_rider":
        registry["briefs"].append(dict(rider))
    elif change == "rider_not_last":
        registry["briefs"] = [rider] + registry["briefs"][:-1]
    elif change == "brief_byte":
        briefs = {profile.PACKET_BRIEF: briefs[profile.PACKET_BRIEF] + b" "}
    elif change == "other_entry":
        registry["briefs"][0]["version"] = registry["briefs"][0]["version"] + 1
    else:
        rider["series"] = "MET-PERF-049/contract"
    mutant = (json.dumps(registry, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
    _raises(V4_MESSAGE, lambda: profile.check_registry(mutant, briefs))


def _hunk_inputs():
    record = profile.authority()
    raw = profile.reviewed_bytes(profile.HUNK_RECORD_PATH)
    afters = {path: profile.reviewed_bytes(path) for path, entry in record["changedFiles"].items() if "reverseHunks" in entry}
    rule = profile._era_rule(profile.READER_PATH, profile.READER_NAME)
    reader = profile._era_model(profile.READER_PATH, profile.READER_NAME)
    context = profile._v24_context(record, json.loads(raw)["hunkClassContext"])
    assert context == reader.context_v24(record, json.loads(raw)["hunkClassContext"])
    return raw, record["changedFiles"], afters, rule.classify, context


@pytest.mark.parametrize("change", ["none", "count", "cascade", "outside"])
def test_v6_the_ledger_classes_are_one_other_per_hunk(change):
    """MON-286-V6A: record.json's classes are exactly one "other" per hunk, and classify is never called for record.json;
    a wrong count, one "cascade" or one class outside the vocabulary is refused."""
    raw, changed, afters, classify, context = _hunk_inputs()
    if profile.LEDGER_PATH not in changed:
        return
    record, called = json.loads(raw), []

    def watched(path, *args, **kwargs):
        called.append(path)
        return classify(path, *args, **kwargs)
    if change == "none":
        assert profile.check_hunk_record(raw, changed, afters, watched, context, profile.HUNK_RULE_SHA256) is None
        assert called and profile.LEDGER_PATH not in called
        assert record["classes"][profile.LEDGER_PATH] == ["other"] * len(changed[profile.LEDGER_PATH]["reverseHunks"])
        return
    message = V6_LEDGER
    if change == "count":
        record["classes"][profile.LEDGER_PATH], message = record["classes"][profile.LEDGER_PATH][:-1], V6_COVER
    elif change == "cascade":
        record["classes"][profile.LEDGER_PATH][0] = "cascade"
    else:
        record["classes"][profile.LEDGER_PATH][-1] = "not-a-class"
    mutant = (json.dumps(record, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
    _raises(message, lambda: profile.check_hunk_record(mutant, changed, afters, watched, context, profile.HUNK_RULE_SHA256))


def test_v6_the_hunk_class_record_holds_for_this_era():
    raw, changed, afters, classify, context = _hunk_inputs()
    assert _sha(raw) == profile.authority()["newFiles"][profile.HUNK_RECORD_PATH]
    assert profile.check_hunk_record(raw, changed, afters, classify, context, profile.HUNK_RULE_SHA256) is None
    assert "other" in set(json.loads(raw)["classes"][READER])


@pytest.mark.parametrize("change", ["member", "authority_path", "statement", "vocabulary", "rule_sha", "reader_rule",
                                    "count_pairs", "file_missing", "count_short", "relabelled"])
def test_v6_the_hunk_class_record_rechecks_in_full(change):
    raw, changed, afters, classify, context = _hunk_inputs()
    record = json.loads(raw)
    rule_sha, message = profile.HUNK_RULE_SHA256, V6_CLOSED
    path = READER
    if change == "member":
        record["extra"] = 1
    elif change == "authority_path":
        record["authorityPath"] = "architecture/other-authority.json"
    elif change == "statement":
        record["outcomeStatements"] = [{"layerSlot": 281, "path": READER, "nodeSha256s": ["0" * 64]}]
    elif change == "vocabulary":
        record["hunkClassVocabulary"], message = record["hunkClassVocabulary"][:-1], V6_PINNED
    elif change == "rule_sha":
        record["hunkClassRuleSha256"], message = "0" * 64, V6_PINNED
    elif change == "reader_rule":
        rule_sha, message = None, V6_PINNED
    elif change == "count_pairs":
        record["hunkClassContext"]["countPairs"], message = [[311, 312]], V6_CONTEXT
    elif change == "file_missing":
        record["classes"].pop(path)
        message = V6_COVER
    elif change == "count_short":
        record["classes"][path] = record["classes"][path][:-1]
        message = V6_COVER
    else:
        position = record["classes"][path].index("other")
        record["classes"][path][position] = "cascade"
        message = V6_RECHECK + "%s hunk %d" % (path, position)
    mutant = (json.dumps(record, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
    _raises(message, lambda: profile.check_hunk_record(mutant, changed, afters, classify, context, rule_sha))
