#!/usr/bin/env python3
"""Fail unless the preprovisioned validation runtime matches the offline lock."""

from __future__ import annotations

import sys
from importlib.metadata import version

EXPECTED = {"jsonschema": "4.24.0", "PyYAML": "6.0.2"}


def main() -> int:
    if sys.version_info[:2] != (3, 12):
        print(
            f"Python 3.12 required, found {sys.version.split()[0]}",
            file=sys.stderr,
        )
        return 2
    for package, wanted in EXPECTED.items():
        found = version(package)
        if found != wanted:
            print(f"{package}=={wanted} required, found {found}", file=sys.stderr)
            return 2
    print("offline toolchain validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
