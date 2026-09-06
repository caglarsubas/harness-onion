"""Deterministic kit packaging plus the entire unchanged predecessor baseline."""
import ast
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

from build import SOURCES, build, candidate_bytes
from common import Refused, digest

ROOT = Path(__file__).resolve().parents[2]
KIT = ROOT / "ci/linux-runner"


def test_byte_identical_package_and_source_inventory(tmp_path):
    root = tmp_path.resolve()
    first = build(KIT, root / "first")
    second = build(KIT, root / "second")
    a = (root / "first/harness-offline-launch.candidate").read_bytes()
    b = (root / "second/harness-offline-launch.candidate").read_bytes()
    assert a == b and first == second
    assert (root / "first/inventory.json").read_bytes() == (root / "second/inventory.json").read_bytes()
    assert first["artifact"]["sha256"] == digest(a)
    assert first["evidence"] == "SOURCE_PACKAGE_ONLY" and first["installed"] is False
    assert first["nativeLinuxAcceptance"] is False
    with zipfile.ZipFile(io.BytesIO(a)) as z:
        assert z.namelist() == sorted([*SOURCES, "__main__.py"])
        for name in z.namelist():
            assert digest(z.read(name)) == first["sourceSha256"][name]
            assert z.getinfo(name).date_time == (1980, 1, 1, 0, 0, 0)
            compile(z.read(name), name, "exec")


def test_packaging_changes_when_candidate_changes(tmp_path):
    for name in SOURCES:
        (tmp_path / name).write_bytes((KIT / name).read_bytes())
    before, _ = candidate_bytes(tmp_path)
    with (tmp_path / "common.py").open("ab") as file:
        file.write(b"\n# synthetic mutation\n")
    assert candidate_bytes(tmp_path)[0] != before


def test_builder_will_not_overwrite_or_install(tmp_path):
    with pytest.raises(Refused):
        build(KIT, tmp_path.resolve())
    with pytest.raises((Refused, OSError)):
        build(KIT, Path("/opt/planeon/bin/new-candidate"))


def test_builder_refuses_root(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(Refused):
        build(KIT, tmp_path / "no-root")


def test_standard_library_only_and_no_shell_evaluation():
    own = {name.removesuffix(".py") for name in SOURCES}
    for file in KIT.glob("*.py"):
        tree = ast.parse(file.read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [alias.name.split(".")[0] for alias in node.names] if isinstance(node, ast.Import) else [node.module.split(".")[0]]
                assert set(names) <= sys.stdlib_module_names | own
            if isinstance(node, ast.Call):
                assert not any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords)
                assert not (isinstance(node.func, ast.Attribute) and node.func.attr in ("system", "popen"))


def test_full_predecessor_suites_and_validators_remain_green():
    # A nested test process stays in this packet's OS-denied tree. Excluding
    # only this new directory prevents recursion, not legacy-test deselection.
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    commands = [[sys.executable, "-m", "pytest", "tests", "--ignore=tests/linux_runner", "ci/test_offline_runner.py", "ci/test_warm_snapshot.py"]]
    commands += [[sys.executable, "scripts/" + name] for name in
                 ("validate_readiness.py", "validate_reuse.py", "validate_alpha2_readiness.py",
                  "validate_readiness_repairs.py", "validate_linux_readiness.py")]
    commands += [[sys.executable, "scripts/zero_bill_scan.py", "."]]
    for argv in commands:
        result = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, text=True, timeout=420, close_fds=True)
        print(result.stdout)
        assert result.returncode == 0, result.stdout + result.stderr
