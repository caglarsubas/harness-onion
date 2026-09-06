"""Manifest-bound case closure; signature mathematics has separate RFC vectors."""
from copy import deepcopy

import pytest

from common import PROOFS, Refused, canonical, digest
import launcher
import preflight


@pytest.fixture
def bound_manifest(manifest, policy, monkeypatch):
    # Synthetic dependency adapter, never a signed host result.
    monkeypatch.setattr(launcher, "verify_signed", lambda *a, **k: None)
    monkeypatch.setattr(launcher.platform, "release", lambda: "synthetic-kernel")
    monkeypatch.setattr(launcher.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(launcher.time, "time", lambda: 150)
    payload = canonical(policy)
    evidence = {"status": "PASS", "scope": "HOST_ISOLATION_ONLY",
                "networkCases": {name: True for name in preflight.NETWORK_CASES},
                "hiddenPathCount": len(policy["warmRoots"]) + len(launcher.hidden_paths(policy)),
                "descendantsChecked": True, **{name: True for name in PROOFS},
                "policySha256": digest(payload), "launcherSha256": digest(b"candidate"),
                "kernel": "synthetic-kernel", "architecture": "x86_64", "observedAt": 140,
                "nativeLinuxAcceptance": False}
    manifest["launcher"]["sha256"] = digest(b"candidate")
    manifest["signature"]["publicKeySha256"] = digest(b"public-key-fixture")
    return manifest, evidence, policy, payload


def check(parts, evidence=None, *, rebind=True):
    manifest, original, policy, payload = deepcopy(parts)
    record = canonical(original if evidence is None else evidence)
    if rebind:
        manifest["preflight"]["evidenceSha256"] = digest(record)
    return launcher.verify_host_manifest(canonical(manifest), b"synthetic-signature", record,
            public=b"synthetic-public", key=b"public-key-fixture", launcher_bytes=b"candidate",
            policy_raw=payload, policy=policy)


def test_all_closed_controls_required(bound_manifest):
    check(bound_manifest)
    for key in bound_manifest[1]:
        evidence = deepcopy(bound_manifest[1])
        del evidence[key]
        with pytest.raises(Refused):
            check(bound_manifest, evidence)


@pytest.mark.parametrize("case", preflight.NETWORK_CASES)
def test_failed_network_case_refused_even_if_summary_claims_pass(bound_manifest, case):
    record = deepcopy(bound_manifest[1])
    record["networkCases"][case] = False
    with pytest.raises(Refused):
        check(bound_manifest, record)


@pytest.mark.parametrize(("field", "value"), [
    ("descendantsChecked", False), ("nativeLinuxAcceptance", True), ("hiddenPathCount", True),
    ("hiddenPathCount", 0), ("observedAt", 151), ("observedAt", -4000), ("observedAt", True),
    ("policySha256", "0" * 64), ("launcherSha256", "0" * 64), ("kernel", "Darwin"),
    ("architecture", "arm64"), ("status", "NOT_RUN_ENV_UNAVAILABLE"), ("networkDenied", 1),
])
def test_stale_incomplete_or_wrong_host_evidence(bound_manifest, field, value):
    record = deepcopy(bound_manifest[1])
    record[field] = value
    with pytest.raises(Refused):
        check(bound_manifest, record)


def test_preflight_digest_mismatch(bound_manifest):
    with pytest.raises(Refused, match="digest"):
        check(bound_manifest, rebind=False)


def test_invalid_manifest_signature_is_not_overridden_by_case_booleans(bound_manifest, monkeypatch):
    def refuse(*args, **kwargs):
        raise Refused("synthetic invalid signature")
    monkeypatch.setattr(launcher, "verify_signed", refuse)
    with pytest.raises(Refused, match="signature"):
        check(bound_manifest)


def test_normal_internal_mode_requires_manifest_descriptors():
    context = {"preflightOnly": False, "authorityDescriptors": {name: 90 + index for index, name in enumerate(launcher.AUTHORITY_FILES)}}
    with pytest.raises(Refused):
        launcher.internal_authority(context)
