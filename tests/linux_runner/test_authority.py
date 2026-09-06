"""Independent malformed-input and RFC 8032 vectors; SOURCE_ONLY."""
from copy import deepcopy
import json
from pathlib import Path

import jsonschema
import pytest

from common import (EXECUTION, Refused, absolute, canonical, digest, disjoint, inventory,
                    packet_commands, parse, root_read, validate_inputs, validate_manifest)
from ed25519 import L, pem_public, verify
from launcher import profile_bytes, validate_policy, verify_signed

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"a":{"x":1,"x":2}}', b'{"x":NaN}', b'{"x":Infinity}', b'{} trailing', b'\xff'])
def test_ambiguous_json(raw):
    with pytest.raises(Refused):
        parse(raw)


@pytest.mark.parametrize("path", ["/", "/home", "/tmp", "relative", "/a/../b", "/a//b", "/a/b/", "/a/b\nprofile x", "/a/${HOME}", "/a/*", "/a/white space", "/a/é"])
def test_unsafe_path(path):
    with pytest.raises(Refused):
        absolute(path)


@pytest.mark.parametrize("paths", [["/a/b", "/a/b/c"], ["/a/b", "/a/b"], ["/a/b/c", "/a/b"]])
def test_overlapping_paths(paths):
    with pytest.raises(Refused):
        disjoint(paths)


def test_manifest_matches_unchanged_schema(manifest):
    schema = json.loads((ROOT / "schemas/trusted-runner-manifest.schema.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(manifest)
    assert validate_manifest(manifest) == manifest["isolation"]["warmSourceRoots"]


@pytest.mark.parametrize(("section", "field", "value"), [
    ("launcher", "ownerUid", False), ("launcher", "ownerGid", 1), ("launcher", "mode", "0777"),
    ("launcher", "path", "/tmp/untrusted"), ("launcher", "sha256", "mutable"),
    ("runner", "ephemeral", 1), ("runner", "ambientCloudCredentials", True),
    ("runner", "sshAgent", True), ("runner", "containerControlSockets", ["/run/docker.sock"]),
    ("runner", "requiredLabels", ["self-hosted"]), ("isolation", "network", "NONE"),
    ("isolation", "warmSourceRoots", ["/srv/warm/a", "/srv/warm/a/child"]),
    ("isolation", "runnerManifestChildMode", "VISIBLE"), ("preflight", "status", "WARN"),
    ("preflight", "networkDenied", 1), ("preflight", "warmMetadataDenied", False),
    ("signature", "algorithm", "NONE"), ("signature", "publicKeyPath", "/tmp/key"),
])
def test_weakened_manifest_refused(manifest, section, field, value):
    manifest[section][field] = value
    with pytest.raises((Refused, TypeError)):
        validate_manifest(manifest)


@pytest.mark.parametrize("section", [None, "launcher", "runner", "isolation", "preflight", "signature"])
def test_unknown_manifest_field(manifest, section):
    (manifest if section is None else manifest[section])["allowEverything"] = True
    with pytest.raises(Refused):
        validate_manifest(manifest)


@pytest.mark.parametrize(("path", "value"), [
    (("target", "os"), "darwin"), (("target", "architecture"), "x86_64"),
    (("target", "execution"), "EMULATED"), (("target", "libc"), "libSystem"),
    (("target", "libcVersion"), "latest"), (("target", "imageDigest"), "linux:latest"),
    (("source", "commit"), "main"), (("source", "repository"), "caglarsubas/agent-hook-v2"),
    (("tools", "python", "version"), "3.11"), (("tools", "python", "path"), "/tmp/python"),
    (("tools", "firejail", "inventorySha256"), ""), (("caches",), []),
    (("caches", 0, "architecture"), "arm64"), (("caches", 0, "inventorySha256"), None),
    (("recipes", "downloads"), "ALLOWED"), (("recipes", "hostOutputReuse"), "ALLOWED"),
])
def test_bad_build_input(inputs, path, value):
    target = inputs
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    with pytest.raises((Refused, TypeError)):
        validate_inputs(inputs)


@pytest.mark.parametrize(("field", "value"), [
    ("issuedAt", True), ("expiresAt", 150), ("expiresAt", 999999), ("operatorUid", 0),
    ("workspace", "/srv/planeon/warm-snapshots/reference"), ("runnerHome", "/home/runner"),
    ("warmRoots", ["/tmp/undeclared"]), ("packetSha256", "main"),
    ("environment", {"API_KEY": "synthetic-secret"}), ("environment", {"UV_CACHE_DIR": "/home/runner/cache"}),
    ("transportPins", {}), ("profileSha256", None),
])
def test_bad_policy(policy, field, value):
    policy[field] = value
    with pytest.raises((Refused, TypeError)):
        validate_policy(policy, 150)


def test_inputs_and_policy_are_deterministic_not_mutated(inputs, policy):
    before = canonical(policy)
    assert validate_inputs(inputs) is inputs
    assert validate_policy(policy, 150) is policy
    assert canonical(policy) == before
    assert digest(profile_bytes(policy)) == policy["profileSha256"]


def packet(prefetch=None, commands=None, execution=None):
    return ("prefetchCommands: " + json.dumps([] if prefetch is None else prefetch) + "\n"
            + "offlineAcceptanceCommands: " + json.dumps([["make", "zero-bill"]] if commands is None else commands) + "\n"
            + "offlineExecution: " + json.dumps(EXECUTION if execution is None else execution) + "\n").encode()


def test_packet_keeps_command_order_and_exact_wrapper():
    commands = [["uv", "run", "--offline", "--frozen", "--no-sync", "python", "-m", "pytest", "tests"], ["make", "zero-bill"]]
    assert packet_commands(packet([["make", "prefetch"]], commands)) == [[["make", "prefetch"]], commands]
    actual = (ROOT / "task-packets/MET-LINUX-002.yaml").read_bytes()
    assert packet_commands(actual)[1][0][-1] == "tests/linux_runner"


@pytest.mark.parametrize("command", [["sh", "x"], ["/bin/bash", "-c", "true"], ["env", "python"], ["python", "-c", "print(1)"],
                                    ["npm", "install"], ["uv", "run", "python", "test.py"], ["make", "verify-offline"], [], ["make", "a\nb"], "make test"])
def test_shell_network_or_ambiguous_argv(command):
    with pytest.raises(Refused):
        packet_commands(packet(commands=[command]))


def test_packet_duplicate_fields_and_bad_phases():
    for raw in (packet() + b"prefetchCommands: []\n", packet([["npm", "ci"]]), packet(commands=[]),
                packet(execution={**EXECUTION, "wrapperArgv": ["sh", "ci/verify-offline.sh"]})):
        with pytest.raises(Refused):
            packet_commands(raw)


# Published RFC 8032 section 7.1 vectors. No signing/private key material exists
# in this kit. Signatures are not generated by the implementation being tested.
VECTORS = [
    ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
]


@pytest.mark.parametrize(("public", "message", "signature"), VECTORS)
def test_rfc8032_known_answer(public, message, signature):
    p, m, s = bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)
    assert verify(p, m, s)
    assert not verify(p, m + b"tamper", s)
    assert not verify(p, m, s[:32] + L.to_bytes(32, "little"))
    verify_signed(m, s, p)
    with pytest.raises(Refused):
        verify_signed(m, s, p, b"different-domain")


@pytest.mark.parametrize("byte", range(64))
def test_every_signature_byte_is_bound(byte):
    p, m, s = (bytes.fromhex(v) for v in VECTORS[0])
    changed = bytearray(s)
    changed[byte] ^= 1
    assert not verify(p, m, bytes(changed))


@pytest.mark.parametrize("public", [bytes(32), b"\x01" + bytes(31), b"\xff" * 32, b"x", b"\xed" + b"\xff" * 30 + b"\x7f"])
def test_invalid_public_encoding(public):
    assert not verify(public, b"", bytes.fromhex(VECTORS[0][2]))


def test_pem_is_ed25519_only():
    import base64
    p = bytes.fromhex(VECTORS[0][0])
    raw = b"-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(bytes.fromhex("302a300506032b6570032100") + p) + b"\n-----END PUBLIC KEY-----\n"
    assert pem_public(raw) == p
    with pytest.raises(ValueError):
        pem_public(raw.replace(b"PUBLIC KEY", b"RSA PUBLIC KEY"))


def test_inventory_rejects_extra_hidden_and_mutated_cache(tmp_path):
    file = tmp_path / "cache.bin"
    file.write_bytes(b"a")
    first = digest(canonical(inventory(tmp_path)))
    assert first == digest(canonical(inventory(tmp_path)))
    file.write_bytes(b"b")
    assert first != digest(canonical(inventory(tmp_path)))
    second = digest(canonical(inventory(tmp_path)))
    (tmp_path / ".extra").write_bytes(b"c")
    assert second != digest(canonical(inventory(tmp_path)))


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo"])
def test_inventory_alias_and_special_refusal(tmp_path, kind):
    import os
    file = tmp_path / "file"
    file.write_bytes(b"no-secret")
    other = tmp_path / "alias"
    if kind == "symlink":
        other.symlink_to(file)
    elif kind == "hardlink":
        os.link(file, other)
    else:
        os.mkfifo(other)
    with pytest.raises(Refused):
        inventory(tmp_path)


def test_user_owned_trust_is_refused(tmp_path):
    path = tmp_path / "authority.json"
    path.write_text("{}")
    with pytest.raises((Refused, OSError)):
        root_read(str(path))
