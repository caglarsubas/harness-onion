#!/usr/bin/env python3
"""Compiled seccomp filter programs (architecture/compiled-filter-programs/, MET-ENFORCE-025): publisher and checker.

The adopted W02d v3 contract (`architecture/seccomp-allowlists-v3/`, MET-ENFORCE-020, merged as 5fab673e) publishes each
role's compiled classic-BPF program only by its SHA-256 (`filterDigests`) and instruction count (`programLengths`). SEC-4
requires the consumers to install exactly those programs, so this packet publishes their bytes (owner decision
Q-HE2S-1 (a), 2026-10-13): the pinned v3 compiler (`scripts/seccomp_allowlists_v3.py`, `compile_filter` and
`program_bytes`) is run on the pinned v3 policy and syscall table, read from their published bytes (each checked against
its pinned digest), and every program is checked against the v3 digest and length before it is written or accepted.

Usage (from the repository root): `python3 -I -B scripts/compiled_filter_programs.py` checks the published files;
`--write` writes them (`programs/<ROLE>.<arch>.bpf` and `index.json`). Standard library only; the v3 compiler is loaded
from its verified bytes (executed as checked, never imported from the file system), never edited or copied.
"""
from __future__ import annotations

import hashlib
import json
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "architecture/compiled-filter-programs"
SCHEMA = "planeon.internal.compiled-filter-programs/v1"
SOURCE_COMMIT = "5fab673e250e7dd0f2ce9c19f6ce9da8cce9321c"
SOURCES = {
    "scripts/seccomp_allowlists_v3.py": "65c1190cf3878222b5cf1dfe032addc1e79b4e2a940ec0d97e0af3a5b8da9c81",
    "architecture/seccomp-allowlists-v3/allowlists.json": "397e79541a7cfaa4f435703703f48f9e1ef54d81a659709d5c80358e0c5bcf66",
    "architecture/seccomp-allowlists-v3/syscalls.json": "863f1df9bc55b7776520790a7314f6fa4b0480f2d58672db0f1f244aa36c7503",
    "architecture/seccomp-allowlists-v3/vectors.json": "18353cb347dc8d4575b650fe4b4ece31f5bf9ca1ce490d1c50a9ae2962f25df8",
}
ARCHES = ("aarch64", "x86_64")
INSTRUCTION_BYTES = 8


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("compiled-filter-programs: " + message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pinned(path: str) -> bytes:
    data = (ROOT / path).read_bytes()
    require(sha256(data) == SOURCES[path], "%s is not the pinned v3 source" % path)
    return data


def compiler(source: bytes) -> types.ModuleType:
    """The v3 compiler from the bytes whose digest was just checked (no import machinery, so no cached bytecode)."""
    module = types.ModuleType("_seccomp_allowlists_v3")
    module.__file__ = "scripts/seccomp_allowlists_v3.py"
    sys.modules[module.__name__] = module
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    return module


def build() -> tuple[dict, dict]:
    """The 14 programs and their index, each checked against the v3 digest and length."""
    sources = {path: pinned(path) for path in SOURCES}
    v3 = compiler(sources["scripts/seccomp_allowlists_v3.py"])
    policy = json.loads(sources["architecture/seccomp-allowlists-v3/allowlists.json"])
    table = json.loads(sources["architecture/seccomp-allowlists-v3/syscalls.json"])
    vectors = json.loads(sources["architecture/seccomp-allowlists-v3/vectors.json"])
    programs, rows = {}, []
    for role in sorted(policy["roles"]):
        for arch in ARCHES:
            program = v3.compile_filter(policy, table, role, arch)
            data = v3.program_bytes(program)
            require(len(data) == INSTRUCTION_BYTES * len(program), "%s %s: 8 bytes per instruction" % (role, arch))
            require("sha256:" + sha256(data) == vectors["filterDigests"][role][arch], "%s %s: v3 digest" % (role, arch))
            require(len(program) == vectors["programLengths"][role][arch], "%s %s: v3 length" % (role, arch))
            path = "programs/%s.%s.bpf" % (role, arch)
            programs[path] = data
            rows.append({"role": role, "arch": arch, "path": path, "instructions": len(program), "bytes": len(data),
                         "sha256": "sha256:" + sha256(data)})
    require(len(rows) == 14, "seven roles on two architectures")
    index = {"schemaVersion": SCHEMA, "evidenceClass": "DATA_CHECK_ONLY",
             "format": "the kernel's struct sock_filter array, 8 bytes per instruction, little-endian (u16 code, u8 jt, "
                       "u8 jf, u32 k), as the pinned compiler's program_bytes emits it",
             "source": {"contract": "architecture/seccomp-allowlists-v3/", "packet": "MET-ENFORCE-020",
                        "commit": SOURCE_COMMIT, "files": {path: "sha256:" + digest for path, digest in SOURCES.items()}},
             "programs": rows}
    return programs, index


def dump(value) -> bytes:
    return (json.dumps(value, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def main(argv: list[str]) -> int:
    programs, index = build()
    if argv == ["--write"]:
        (OUT / "programs").mkdir(parents=True, exist_ok=True)
        for path, data in programs.items():
            (OUT / path).write_bytes(data)
        (OUT / "index.json").write_bytes(dump(index))
        print("wrote %d programs and index.json" % len(programs))
        return 0
    require(argv == [], "usage: compiled_filter_programs.py [--write]")
    folder = OUT / "programs"
    present = sorted(p.relative_to(OUT).as_posix() for p in folder.iterdir()) if folder.is_dir() else []
    require(present == sorted(programs), "programs/ holds exactly the 14 programs")
    for path, data in programs.items():
        require((OUT / path).read_bytes() == data, "%s differs from the pinned compiler's output" % path)
    index_path = OUT / "index.json"
    require(index_path.is_file() and index_path.read_bytes() == dump(index), "index.json differs")
    print("compiled filter programs: %d programs equal the pinned v3 compiler's output and the v3 digests" % len(programs))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
