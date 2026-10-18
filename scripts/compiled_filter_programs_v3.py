#!/usr/bin/env python3
"""Compiled seccomp filter programs v3 (architecture/compiled-filter-programs-v3/, MET-ENFORCE-036): publisher and checker.

The adopted seccomp allowlists v5 (`architecture/seccomp-allowlists-v5/`, MET-ENFORCE-035, merged as f4bb0000) add one
OBSERVER duty to v4: the I01 AF_UNIX SOCK_SEQPACKET listener, `bind` and `listen` unconditioned and `accept4` only with
flags 0, SOCK_CLOEXEC or SOCK_CLOEXEC|SOCK_NONBLOCK (W01 amendment HS53, H1). Only OBSERVER's compiled program changes, on
both architectures; the other twelve programs are byte-identical to the ones MET-ENFORCE-029's index lists (EFFECT_GATE's
in `architecture/compiled-filter-programs-v2/`, the other ten in `architecture/compiled-filter-programs/`). This successor
republishes the two OBSERVER programs from v5 (HS53 obligation O-PROGRAMS-V3-OBSERVER; the lane monitor's Q-P2-1..4,
2026-10-18) and indexes all fourteen v5 programs.

The pinned v5 model (`scripts/seccomp_allowlists_v5.py`, `compile_filter`, `program_bytes` and `run_filter`) is run on the
pinned v5 policy, syscall table and vectors, each read from its published bytes and checked against its pinned digest.
Before anything is written or accepted:
- every program equals v5's `filterDigests` and `programLengths`;
- the twelve programs of the other roles equal, byte for byte, the files MET-ENFORCE-029's index lists (which equal it);
- each OBSERVER program equals the earlier OBSERVER program with exactly two blocks inserted at the recorded indexes,
  restated here instruction by instruction, and nothing else different: the four-instruction `bind`/`listen` pair and the
  eleven-instruction `accept4` flag block;
- every v5 OBSERVER decision vector runs through the published bytes to its recorded action.

Usage (from the repository root): `python3 -I -B scripts/compiled_filter_programs_v3.py` checks the published files;
`--write` writes them (`programs/OBSERVER.<arch>.bpf` and `index.json`). Standard library only; the v5 model is loaded
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
OUT_DIR = "architecture/compiled-filter-programs-v3/"
OUT = ROOT / OUT_DIR
SCHEMA = "planeon.internal.compiled-filter-programs/v3"
FORMAT = ("the kernel's struct sock_filter array, 8 bytes per instruction, little-endian (u16 code, u8 jt, u8 jf, u32 k), "
          "as the pinned compiler's program_bytes emits it")
MODEL = "scripts/seccomp_allowlists_v5.py"
V5_DIR = "architecture/seccomp-allowlists-v5/"
SOURCE_PACKET = "MET-ENFORCE-035"
SOURCE_COMMIT = "f4bb0000df9ec4bdaac54d3e6488d691e2001f28"
SOURCES = {
    MODEL: "fc57bb40f4f2537005e46689d9fc39a0dd98d4ebe141f9aace961e9520f1e0a7",
    V5_DIR + "allowlists.json": "879909a86037b153a951770b4a47a8c075364fbd7cf9a44405537807621b55a8",
    V5_DIR + "syscalls.json": "fe9a603e780b576f666a219da119eedad5271a675998aba2d6d581fb53ebac07",
    V5_DIR + "vectors.json": "4539410a9bb66e2aca62931567253c3c70b382672cc2b8f8207d4ea3d4661ecd",
}
PREDECESSOR_INDEX = "architecture/compiled-filter-programs-v2/index.json"
PREDECESSOR_INDEX_SHA256 = "59581bbfb75e81f364382833b94be6c42f4e2a658c49711b4e72712434ef69cb"
PREDECESSOR_PACKET = "MET-ENFORCE-029"
ARCHES = ("aarch64", "x86_64")
INSTRUCTION_BYTES = 8
ROLE = "OBSERVER"
# Where v5's two rules enter the earlier OBSERVER program: instruction indexes in that program, before which the
# bind/listen pair and the accept4 block are inserted.
PAIR_AT = {"aarch64": 134, "x86_64": 110}
ACCEPT4_AT = {"aarch64": 175, "x86_64": 184}
# Classic-BPF opcodes and seccomp return values, restated (include/uapi/linux/filter.h, bpf_common.h, seccomp.h).
LD_W_ABS, JEQ_K, RET_K = 0x20, 0x15, 0x06
RET_ALLOW, RET_KILL_PROCESS = 0x7FFF0000, 0x80000000
# struct seccomp_data: args[3] starts at 16 + 3 * 8; little-endian, so its low word is there (v5's rule compares it).
ARG3_LOW = 0x28
ACCEPT4_FLAGS = (0, 0x80000, 0x80800)
# v5's OBSERVER decision vectors per architecture, and how many of them test bind, listen or accept4.
OBSERVER_DECISIONS = {"aarch64": 256, "x86_64": 267}
OBSERVER_LISTENER_DECISIONS = 44


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("compiled-filter-programs-v3: " + message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pinned(path: str, expected: str) -> bytes:
    data = (ROOT / path).read_bytes()
    require(sha256(data) == expected, "%s is not the pinned source" % path)
    return data


def compiler(source: bytes) -> types.ModuleType:
    """The v5 model from the bytes whose digest was just checked (no import machinery, so no cached bytecode)."""
    module = types.ModuleType("_seccomp_allowlists_v5")
    module.__file__ = MODEL
    sys.modules[module.__name__] = module
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    return module


def pack(block: list) -> bytes:
    return b"".join(struct.pack("<HBBI", *instruction) for instruction in block)


def listener_pair(bind_nr: int, listen_nr: int) -> bytes:
    """The four instructions for bind and listen: each a number test that allows, otherwise falls through."""
    return pack([(JEQ_K, 0, 1, bind_nr), (RET_K, 0, 0, RET_ALLOW), (JEQ_K, 0, 1, listen_nr), (RET_K, 0, 0, RET_ALLOW)])


def accept4_block(nr: int) -> bytes:
    """The eleven instructions for accept4: the number test, then per allowed flag value load args[3]'s low word, compare
    and allow; any other value kills."""
    block = [(JEQ_K, 0, 10, nr)]
    for flags in ACCEPT4_FLAGS:
        block += [(LD_W_ABS, 0, 0, ARG3_LOW), (JEQ_K, 0, 1, flags), (RET_K, 0, 0, RET_ALLOW)]
    return pack(block + [(RET_K, 0, 0, RET_KILL_PROCESS)])


def decode(data: bytes) -> list[tuple[int, int, int, int]]:
    require(len(data) % INSTRUCTION_BYTES == 0, "a program is a whole number of instructions")
    return [struct.unpack_from("<HBBI", data, offset) for offset in range(0, len(data), INSTRUCTION_BYTES)]


def build() -> tuple[dict, dict, tuple]:
    """The two OBSERVER programs, the index of all fourteen, and the v5 model, table and vectors for the replay."""
    sources = {path: pinned(path, digest) for path, digest in SOURCES.items()}
    v5 = compiler(sources[MODEL])
    policy = json.loads(sources[V5_DIR + "allowlists.json"])
    table = json.loads(sources[V5_DIR + "syscalls.json"])
    vectors = json.loads(sources[V5_DIR + "vectors.json"])
    predecessor = json.loads(pinned(PREDECESSOR_INDEX, PREDECESSOR_INDEX_SHA256))
    earlier = {(row["role"], row["arch"]): row for row in predecessor["programs"]}
    require(sorted(earlier) == [(role, arch) for role in sorted(policy["roles"]) for arch in ARCHES],
            "MET-ENFORCE-029's index lists the same fourteen programs")
    programs, rows = {}, []
    for role in sorted(policy["roles"]):
        for arch in ARCHES:
            program = v5.compile_filter(policy, table, role, arch)
            data = v5.program_bytes(program)
            require(len(data) == INSTRUCTION_BYTES * len(program), "%s %s: 8 bytes per instruction" % (role, arch))
            require("sha256:" + sha256(data) == vectors["filterDigests"][role][arch], "%s %s: v5 digest" % (role, arch))
            require(len(program) == vectors["programLengths"][role][arch], "%s %s: v5 length" % (role, arch))
            row = earlier[role, arch]
            prior = (ROOT / row["path"]).read_bytes()
            require("sha256:" + sha256(prior) == row["sha256"] and len(prior) == row["bytes"]
                    == INSTRUCTION_BYTES * row["instructions"], "%s %s: the indexed file is its index's" % (role, arch))
            if role == ROLE:
                nr = {name: table["syscalls"][name][arch]["nr"] for name in ("bind", "listen", "accept4")}
                pair, accept = INSTRUCTION_BYTES * PAIR_AT[arch], INSTRUCTION_BYTES * ACCEPT4_AT[arch]
                require(pair < accept <= len(prior)
                        and data == prior[:pair] + listener_pair(nr["bind"], nr["listen"]) + prior[pair:accept]
                        + accept4_block(nr["accept4"]) + prior[accept:],
                        "%s %s: the earlier program with exactly the bind/listen pair at %d and the accept4 block at %d"
                        % (role, arch, PAIR_AT[arch], ACCEPT4_AT[arch]))
                path = OUT_DIR + "programs/%s.%s.bpf" % (role, arch)
                programs[path] = data
            else:
                require(data == prior, "%s %s: byte-identical to the indexed program" % (role, arch))
                path = row["path"]
            rows.append({"role": role, "arch": arch, "path": path, "instructions": len(program), "bytes": len(data),
                         "sha256": "sha256:" + sha256(data)})
    require(len(rows) == 14 and len(programs) == 2, "seven roles on two architectures; OBSERVER's two republished")
    index = {"schemaVersion": SCHEMA, "evidenceClass": "DATA_CHECK_ONLY", "format": FORMAT,
             "source": {"contract": V5_DIR, "packet": SOURCE_PACKET, "commit": SOURCE_COMMIT,
                        "files": {path: "sha256:" + digest for path, digest in SOURCES.items()}},
             "predecessor": {"path": PREDECESSOR_INDEX, "sha256": "sha256:" + PREDECESSOR_INDEX_SHA256,
                             "packet": PREDECESSOR_PACKET},
             "programs": rows}
    return programs, index, (v5, table, vectors)


def replay(model: tuple, published: dict) -> tuple[dict, int]:
    """Every v5 OBSERVER decision vector, run through the published bytes, gives its recorded action."""
    v5, table, vectors = model
    observer = {arch: decode(published[OUT_DIR + "programs/%s.%s.bpf" % (ROLE, arch)]) for arch in ARCHES}
    counts, listener = {arch: 0 for arch in ARCHES}, 0
    for row in vectors["decisionChecks"]:
        if row["role"] != ROLE:
            continue
        action = v5.run_filter(observer[row["arch"]], v5.seccomp_data(row["nr"], row["auditArch"], row["args"]))
        require(v5.action_name(action) == row["expect"], "decision vector %s through the published bytes" % row["id"])
        counts[row["arch"]] += 1
        listener += row["nr"] in {table["syscalls"][name][row["arch"]]["nr"] for name in ("bind", "listen", "accept4")}
    require(counts == OBSERVER_DECISIONS and listener == OBSERVER_LISTENER_DECISIONS,
            "the replay covers v5's OBSERVER decision vectors: %r, listener calls %d" % (counts, listener))
    return counts, listener


def dump(value) -> bytes:
    return (json.dumps(value, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def report(counts: dict, listener: int) -> str:
    return ("14 programs equal the pinned v5 model's output and v5's digests and lengths; 12 are byte-identical to the "
            "programs MET-ENFORCE-029 indexes; OBSERVER is the earlier program plus the bind/listen pair and the accept4 "
            "block (%s); %d OBSERVER decision vectors replayed through the published bytes (%s; %d listener calls)"
            % (", ".join("%s at %d and %d" % (arch, PAIR_AT[arch], ACCEPT4_AT[arch]) for arch in ARCHES),
               sum(counts.values()), ", ".join("%s %d" % (arch, counts[arch]) for arch in ARCHES), listener))


def main(argv: list[str]) -> int:
    programs, index, model = build()
    if argv == ["--write"]:
        counts, listener = replay(model, programs)
        (OUT / "programs").mkdir(parents=True, exist_ok=True)
        for path, data in programs.items():
            (ROOT / path).write_bytes(data)
        (OUT / "index.json").write_bytes(dump(index))
        print("wrote %d programs and index.json: %s" % (len(programs), report(counts, listener)))
        return 0
    require(argv == [], "usage: compiled_filter_programs_v3.py [--write]")
    present = sorted(OUT_DIR + "programs/" + entry.name for entry in (OUT / "programs").iterdir()) \
        if (OUT / "programs").is_dir() else []
    require(present == sorted(programs), "programs/ holds exactly the two OBSERVER programs")
    published = {path: (ROOT / path).read_bytes() for path in programs}
    for path, data in programs.items():
        require(published[path] == data, "%s differs from the pinned model's output" % path)
    counts, listener = replay(model, published)
    index_path = OUT / "index.json"
    require(index_path.is_file() and index_path.read_bytes() == dump(index), "index.json differs")
    print("compiled filter programs v3: " + report(counts, listener))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
