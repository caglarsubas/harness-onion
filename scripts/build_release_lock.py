#!/usr/bin/env python3
"""Build deterministic canonical JSON from one validated release-set source."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

try:
    from check_release_lock import ReleaseLockError, validate_release_lock
except ModuleNotFoundError:  # pragma: no cover - module import path in unit tests
    from scripts.check_release_lock import ReleaseLockError, validate_release_lock


def build_release_lock(source: Path, destination: Path) -> str:
    """Validate source, then create destination exclusively as canonical JSON."""

    if source.resolve() == destination.resolve():
        raise ReleaseLockError("source and destination must differ")
    if destination.suffix.casefold() != ".json":
        raise ReleaseLockError("destination must use the .json suffix")
    document, _ = validate_release_lock(source)
    encoded = json.dumps(
        document,
        indent=2,
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    ) + "\n"
    try:
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o644,
        )
    except OSError as exc:
        raise ReleaseLockError(f"cannot create {destination}: {exc}") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return encoded


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args(argv)
    try:
        build_release_lock(arguments.source, arguments.destination)
    except ReleaseLockError as exc:
        print(f"release lock build failed: {exc}", file=sys.stderr)
        return 2
    print(f"canonical release lock created: {arguments.destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
