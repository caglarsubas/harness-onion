"""Native bytes and exhaustive system closure admission; no host qualification."""
from copy import deepcopy

import pytest

from common import Refused, validate_inputs
import launcher


def elf(machine):
    return b"\x7fELF\x02\x01" + bytes(12) + machine.to_bytes(2, "little") + bytes(44)


@pytest.mark.parametrize(("arch", "machine"), [("amd64", 62), ("arm64", 183)])
def test_expected_native_elf(arch, machine):
    launcher.validate_elf(elf(machine), arch)


@pytest.mark.parametrize(("raw", "arch"), [(elf(62), "arm64"), (elf(183), "amd64"),
    (b"\xcf\xfa\xed\xfe" + bytes(60), "arm64"), (b"MZ" + bytes(62), "amd64"),
    (b"#!/usr/bin/python\n", "amd64"), (b"\x7fELF", "amd64"), (elf(62)[:4] + b"\x01\x01" + elf(62)[6:], "amd64")])
def test_wrong_native_binary_refused(raw, arch):
    with pytest.raises(Refused):
        launcher.validate_elf(raw, arch)


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "writable-place", "unbound-cache", "unknown-field"])
def test_system_helper_and_loader_pins_required(inputs, mutation):
    if mutation == "missing":
        inputs["systemTrees"] = []
    elif mutation == "duplicate":
        inputs["systemTrees"].append(deepcopy(inputs["systemTrees"][0]))
    elif mutation == "writable-place":
        inputs["systemTrees"][0]["root"] = "/tmp/libraries"
    elif mutation == "unbound-cache":
        inputs["systemFiles"] = {}
    else:
        inputs["systemFiles"]["/etc/ld.so.preload"] = "0" * 64
    with pytest.raises(Refused):
        validate_inputs(inputs)


def test_unobservable_libc_cannot_pass_by_label(inputs, monkeypatch):
    monkeypatch.setattr(launcher.platform, "system", lambda: "Linux")
    monkeypatch.setattr(launcher.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(launcher.platform, "libc_ver", lambda: ("", ""))
    with pytest.raises(Refused, match="libc"):
        launcher.verify_tools(inputs)


def test_global_loader_injection_refused_before_inventory(inputs, monkeypatch):
    monkeypatch.setattr(launcher.platform, "system", lambda: "Linux")
    monkeypatch.setattr(launcher.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(launcher.platform, "libc_ver", lambda: ("glibc", "2.39"))
    monkeypatch.setattr(launcher.os.path, "lexists", lambda path: path == "/etc/ld.so.preload")
    monkeypatch.setattr(launcher, "inventory", lambda *a, **k: pytest.fail("loader rejection must happen first"))
    with pytest.raises(Refused, match="loader injection"):
        launcher.verify_tools(inputs)
