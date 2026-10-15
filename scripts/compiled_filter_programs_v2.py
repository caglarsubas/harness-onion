#!/usr/bin/env python3
"""Compiled seccomp filter programs v2 (architecture/compiled-filter-programs-v2/, MET-ENFORCE-029): publisher and checker.

The adopted seccomp allowlists v4 (`architecture/seccomp-allowlists-v4/`, MET-ENFORCE-027, merged as e7516160) add one
EFFECT_GATE duty to v3: `readlinkat` only with a non-negative dirfd. Only EFFECT_GATE's compiled program changes, on both
architectures; the other twelve programs are byte-identical to the ones MET-ENFORCE-025 published in
`architecture/compiled-filter-programs/`. This successor republishes the two EFFECT_GATE programs from v4 (owner decisions
Q-HE3A-1 (c) and Q-HE3A-1b (a), 2026-10-13; Q-PR-1..10 (a), 2026-10-15) and indexes all fourteen v4 programs.

The pinned v4 model (`scripts/seccomp_allowlists_v4.py`, `compile_filter`, `program_bytes` and `run_filter`) is run on the
pinned v4 policy, syscall table and vectors, each read from its published bytes and checked against its pinned digest.
Before anything is written or accepted:
- every program equals v4's `filterDigests` and `programLengths`;
- the twelve programs of the other roles equal, byte for byte, MET-ENFORCE-025's files (which equal its pinned index);
- each EFFECT_GATE program equals MET-ENFORCE-025's v3 EFFECT_GATE program with exactly the six-instruction `readlinkat`
  block inserted at the recorded index, and nothing else different (Q-PR-6);
- every v4 EFFECT_GATE decision vector runs through the published bytes to its recorded action (Q-PR-7).

Usage (from the repository root): `python3 -I -B scripts/compiled_filter_programs_v2.py` checks the published files;
`--write` writes them (`programs/EFFECT_GATE.<arch>.bpf` and `index.json`). Standard library only; the v4 model is loaded
from its verified bytes (executed as checked, never imported from the file system), never edited or copied.
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = "architecture/compiled-filter-programs-v2/"
OUT = ROOT / OUT_DIR
SCHEMA = "planeon.internal.compiled-filter-programs/v2"
FORMAT = ("the kernel's struct sock_filter array, 8 bytes per instruction, little-endian (u16 code, u8 jt, u8 jf, u32 k), "
          "as the pinned compiler's program_bytes emits it")
MODEL = "scripts/seccomp_allowlists_v4.py"
V4_DIR = "architecture/seccomp-allowlists-v4/"
SOURCE_PACKET = "MET-ENFORCE-027"
SOURCE_COMMIT = "e7516160468c213862b337b344d240fde5f7328c"
SOURCES = {
    MODEL: "f88e3eab1a154260b2a33d7a1eadb5a78f29d49579219d3aaf55041ec861e9bf",
    V4_DIR + "allowlists.json": "4dcfb2dfea82eabd04024b35d9dac4bb487b6c0051f7e6e16bbd00426cf6b2ff",
    V4_DIR + "syscalls.json": "d759e341afcbcf2dccd8eafce136a303d2275efceeac1525ef2200b6e65fe53d",
    V4_DIR + "vectors.json": "9a918c15bbcb6378b282df9a5da8389289bf505f9f8eb5e1a50b9c5bb6f92187",
}
PREDECESSOR_DIR = "architecture/compiled-filter-programs/"
PREDECESSOR_INDEX = PREDECESSOR_DIR + "index.json"
PREDECESSOR_INDEX_SHA256 = "9136ce1f450ad8bba0810e23ab5324e9e156cb851b1afefbf2f3f84b28d2cef7"
PREDECESSOR_PACKET = "MET-ENFORCE-025"
ARCHES = ("aarch64", "x86_64")
INSTRUCTION_BYTES = 8
GATE = "EFFECT_GATE"
# Where v4's one new rule enters the v3 EFFECT_GATE program: (instruction index, readlinkat syscall number).
BLOCK_AT = {"aarch64": (34, 78), "x86_64": (173, 267)}
# Classic-BPF opcodes and seccomp return values, restated (include/uapi/linux/filter.h, bpf_common.h, seccomp.h).
LD_W_ABS, JEQ_K, AND_K, RET_K = 0x20, 0x15, 0x54, 0x06
RET_ALLOW, RET_KILL_PROCESS = 0x7FFF0000, 0x80000000
# v4's EFFECT_GATE decision vectors per architecture, and how many of them test readlinkat.
GATE_DECISIONS = {"aarch64": 195, "x86_64": 206}
GATE_READLINKAT_DECISIONS = 20


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("compiled-filter-programs-v2: " + message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pinned(path: str, expected: str) -> bytes:
    data = (ROOT / path).read_bytes()
    require(sha256(data) == expected, "%s is not the pinned source" % path)
    return data


def compiler(source: bytes) -> types.ModuleType:
    """The v4 model from the bytes whose digest was just checked (no import machinery, so no cached bytecode)."""
    module = types.ModuleType("_seccomp_allowlists_v4")
    module.__file__ = MODEL
    sys.modules[module.__name__] = module
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    return module


def readlinkat_block(nr: int) -> bytes:
    """The six instructions v4's rule adds: number test, load arg 0's low word, keep bit 31, require it clear, allow,
    otherwise kill."""
    block = [(JEQ_K, 0, 5, nr), (LD_W_ABS, 0, 0, 0x10), (AND_K, 0, 0, 0x80000000), (JEQ_K, 0, 1, 0),
             (RET_K, 0, 0, RET_ALLOW), (RET_K, 0, 0, RET_KILL_PROCESS)]
    return b"".join(struct.pack("<HBBI", *instruction) for instruction in block)


def decode(data: bytes) -> list[tuple[int, int, int, int]]:
    require(len(data) % INSTRUCTION_BYTES == 0, "a program is a whole number of instructions")
    return [struct.unpack_from("<HBBI", data, offset) for offset in range(0, len(data), INSTRUCTION_BYTES)]


def build() -> tuple[dict, dict, tuple]:
    """The two EFFECT_GATE programs, the index of all fourteen, and the v4 model, table and vectors for the replay."""
    sources = {path: pinned(path, digest) for path, digest in SOURCES.items()}
    v4 = compiler(sources[MODEL])
    policy = json.loads(sources[V4_DIR + "allowlists.json"])
    table = json.loads(sources[V4_DIR + "syscalls.json"])
    vectors = json.loads(sources[V4_DIR + "vectors.json"])
    predecessor = json.loads(pinned(PREDECESSOR_INDEX, PREDECESSOR_INDEX_SHA256))
    earlier = {(row["role"], row["arch"]): row for row in predecessor["programs"]}
    require(sorted(earlier) == [(role, arch) for role in sorted(policy["roles"]) for arch in ARCHES],
            "MET-ENFORCE-025's index lists the same fourteen programs")
    programs, rows = {}, []
    for role in sorted(policy["roles"]):
        for arch in ARCHES:
            program = v4.compile_filter(policy, table, role, arch)
            data = v4.program_bytes(program)
            require(len(data) == INSTRUCTION_BYTES * len(program), "%s %s: 8 bytes per instruction" % (role, arch))
            require("sha256:" + sha256(data) == vectors["filterDigests"][role][arch], "%s %s: v4 digest" % (role, arch))
            require(len(program) == vectors["programLengths"][role][arch], "%s %s: v4 length" % (role, arch))
            row = earlier[role, arch]
            require(row["path"] == "programs/%s.%s.bpf" % (role, arch), "%s %s: MET-ENFORCE-025's path" % (role, arch))
            v3 = (ROOT / (PREDECESSOR_DIR + row["path"])).read_bytes()
            require("sha256:" + sha256(v3) == row["sha256"] and len(v3) == row["bytes"]
                    == INSTRUCTION_BYTES * row["instructions"], "%s %s: MET-ENFORCE-025's file is its index's" % (role, arch))
            if role == GATE:
                index, nr = BLOCK_AT[arch]
                require(table["syscalls"]["readlinkat"][arch]["nr"] == nr, "%s: readlinkat is syscall %d" % (arch, nr))
                at = INSTRUCTION_BYTES * index
                require(data == v3[:at] + readlinkat_block(nr) + v3[at:],
                        "%s %s: v3's program with exactly the six-instruction readlinkat block at %d" % (role, arch, index))
                path = OUT_DIR + "programs/%s.%s.bpf" % (role, arch)
                programs[path] = data
            else:
                require(data == v3, "%s %s: byte-identical to MET-ENFORCE-025's program" % (role, arch))
                path = PREDECESSOR_DIR + row["path"]
            rows.append({"role": role, "arch": arch, "path": path, "instructions": len(program), "bytes": len(data),
                         "sha256": "sha256:" + sha256(data)})
    require(len(rows) == 14 and len(programs) == 2, "seven roles on two architectures; EFFECT_GATE's two republished")
    index = {"schemaVersion": SCHEMA, "evidenceClass": "DATA_CHECK_ONLY", "format": FORMAT,
             "source": {"contract": V4_DIR, "packet": SOURCE_PACKET, "commit": SOURCE_COMMIT,
                        "files": {path: "sha256:" + digest for path, digest in SOURCES.items()}},
             "predecessor": {"path": PREDECESSOR_INDEX, "sha256": "sha256:" + PREDECESSOR_INDEX_SHA256,
                             "packet": PREDECESSOR_PACKET},
             "programs": rows}
    return programs, index, (v4, table, vectors)


def replay(model: tuple, published: dict) -> tuple[dict, int]:
    """Every v4 EFFECT_GATE decision vector, run through the published bytes, gives its recorded action."""
    v4, table, vectors = model
    gate = {arch: decode(published[OUT_DIR + "programs/%s.%s.bpf" % (GATE, arch)]) for arch in ARCHES}
    counts, readlinkat = {arch: 0 for arch in ARCHES}, 0
    for row in vectors["decisionChecks"]:
        if row["role"] != GATE:
            continue
        action = v4.run_filter(gate[row["arch"]], v4.seccomp_data(row["nr"], row["auditArch"], row["args"]))
        require(v4.action_name(action) == row["expect"], "decision vector %s through the published bytes" % row["id"])
        counts[row["arch"]] += 1
        readlinkat += row["nr"] == table["syscalls"]["readlinkat"][row["arch"]]["nr"]
    require(counts == GATE_DECISIONS and readlinkat == GATE_READLINKAT_DECISIONS,
            "the replay covers v4's EFFECT_GATE decision vectors: %r, readlinkat %d" % (counts, readlinkat))
    return counts, readlinkat


def dump(value) -> bytes:
    return (json.dumps(value, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def report(counts: dict, readlinkat: int) -> str:
    return ("14 programs equal the pinned v4 model's output and v4's digests and lengths; 12 are byte-identical to "
            "MET-ENFORCE-025's; EFFECT_GATE is v3's program plus the readlinkat block (%s); %d EFFECT_GATE decision "
            "vectors replayed through the published bytes (%s; %d readlinkat)"
            % (", ".join("%s at %d, nr %d" % (arch, *BLOCK_AT[arch]) for arch in ARCHES), sum(counts.values()),
               ", ".join("%s %d" % (arch, counts[arch]) for arch in ARCHES), readlinkat))


def main(argv: list[str]) -> int:
    programs, index, model = build()
    if argv == ["--write"]:
        counts, readlinkat = replay(model, programs)
        (OUT / "programs").mkdir(parents=True, exist_ok=True)
        for path, data in programs.items():
            (ROOT / path).write_bytes(data)
        (OUT / "index.json").write_bytes(dump(index))
        print("wrote %d programs and index.json: %s" % (len(programs), report(counts, readlinkat)))
        return 0
    require(argv == [], "usage: compiled_filter_programs_v2.py [--write]")
    present = sorted(OUT_DIR + "programs/" + entry.name for entry in (OUT / "programs").iterdir()) \
        if (OUT / "programs").is_dir() else []
    require(present == sorted(programs), "programs/ holds exactly the two EFFECT_GATE programs")
    published = {path: (ROOT / path).read_bytes() for path in programs}
    for path, data in programs.items():
        require(published[path] == data, "%s differs from the pinned model's output" % path)
    counts, readlinkat = replay(model, published)
    index_path = OUT / "index.json"
    require(index_path.is_file() and index_path.read_bytes() == dump(index), "index.json differs")
    print("compiled filter programs v2: " + report(counts, readlinkat))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
