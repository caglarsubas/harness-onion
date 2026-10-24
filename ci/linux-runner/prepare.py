"""Render an unsigned operator policy/profile pair; no keys, install or probes."""
import argparse
import os
from pathlib import Path
import time

from common import INPUTS_V4, canonical, digest, parse, require, root_aliases
from launcher import profile_bytes, validate_policy


def prepare(request, destination, now, root_aliases_raw=None):
    require(os.geteuid() != 0, "prepare must be unprivileged")
    require(type(request) is dict and "profileSha256" not in request, "profile digest is computed, not caller asserted")
    policy = {**request, "profileSha256": "0" * 64}
    # Structural validation must precede rendering paths into profile syntax.
    validate_policy(policy, now)
    # MET-LINUX-009: a v4 request needs its root-alias record; a v3 request may not carry one.
    require((policy["inputs"]["schemaVersion"] == INPUTS_V4) == (root_aliases_raw is not None),
            "root alias record only and always for v4 inputs")
    root_aliases(root_aliases_raw, policy["inputs"])
    profile = profile_bytes(policy)
    policy["profileSha256"] = digest(profile)
    destination = Path(destination)
    require(destination.is_absolute() and destination.parent.resolve(strict=True) == destination.parent
            and destination.parent.stat().st_uid == os.getuid() and not destination.exists()
            and not destination.is_symlink(), "new private output directory required")
    require(not any(Path(root) == destination or Path(root) in destination.parents for root in ("/etc", "/opt", "/usr", "/bin", "/sbin")), "no installation")
    destination.mkdir(mode=0o700)
    for name, data in (("policy.json.unsigned", canonical(policy)), ("firejail.profile.candidate", profile)):
        with (destination / name).open("xb") as stream:
            stream.write(data)
    return {"status": "UNSIGNED_CANDIDATE", "policySha256": digest(canonical(policy)),
            "profileSha256": digest(profile), "installed": False, "nativeLinuxAcceptance": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--root-aliases", type=Path)
    args = parser.parse_args()
    require(args.request.is_file() and not args.request.is_symlink(), "request must be regular")
    raw = None
    if args.root_aliases is not None:
        require(args.root_aliases.is_file() and not args.root_aliases.is_symlink(), "root alias record must be regular")
        raw = args.root_aliases.read_bytes()
    print(canonical(prepare(parse(args.request.read_bytes()), args.output, int(time.time()), raw)).decode())


if __name__ == "__main__":
    main()
