"""Deterministic, unprivileged candidate packaging. Never installs or signs."""
from __future__ import annotations

import argparse
import io
import os
from pathlib import Path
import zipfile

from common import PYTHON, VERSION, canonical, digest, require

SOURCES = ("common.py", "ed25519.py", "launcher.py", "preflight.py")


def candidate_bytes(source):
    output = io.BytesIO()
    output.write(("#!" + PYTHON + " -IB\n").encode())
    members = {name: (source / name).read_bytes() for name in SOURCES}
    members["__main__.py"] = b"from launcher import main\nraise SystemExit(main())\n"
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in sorted(members.items()):
            require(not (source / name).is_symlink(), "source symlink")
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100444 << 16
            archive.writestr(info, data)
    return output.getvalue(), {name: digest(raw) for name, raw in sorted(members.items())}


def build(source, destination):
    require(os.geteuid() != 0, "candidate builder must be unprivileged")
    source, destination = Path(source), Path(destination)
    require(destination.is_absolute() and not destination.exists() and not destination.is_symlink()
            and destination.parent.resolve(strict=True) == destination.parent
            and destination.parent.stat().st_uid == os.getuid(), "new caller-owned output directory required")
    require(not any(Path(root) == destination or Path(root) in destination.parents
                    for root in ("/etc", "/opt", "/usr", "/bin", "/sbin")), "installation path forbidden")
    raw, members = candidate_bytes(source)
    destination.mkdir(mode=0o700)
    artifact = destination / "harness-offline-launch.candidate"
    with artifact.open("xb") as stream:
        stream.write(raw)
    artifact.chmod(0o555)
    record = {"schemaVersion": "planeon.linux-runner-candidate/v1", "version": VERSION,
              "evidence": "SOURCE_PACKAGE_ONLY", "installed": False, "nativeLinuxAcceptance": False,
              "artifact": {"path": artifact.name, "sha256": digest(raw), "size": len(raw), "mode": "0555"},
              "sourceSha256": members, "interpreter": PYTHON}
    with (destination / "inventory.json").open("xb") as stream:
        stream.write(canonical(record) + b"\n")
    return record


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(canonical(build(Path(__file__).resolve().parent, args.output)).decode())


if __name__ == "__main__":
    main()
