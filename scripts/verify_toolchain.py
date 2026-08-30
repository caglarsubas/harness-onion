#!/usr/bin/env python3
"""Fail unless the preprovisioned validation runtime matches the offline lock."""

from __future__ import annotations

import sys
from importlib.metadata import distributions, version

EXPECTED = {"jsonschema": "4.24.0", "PyYAML": "6.0.2"}
EXACT_ENVIRONMENT = {
    **EXPECTED,
    "attrs": "26.1.0",
    "iniconfig": "2.3.0",
    "jsonschema-specifications": "2025.9.1",
    "packaging": "26.3",
    "pluggy": "1.6.0",
    "Pygments": "2.21.0",
    "pytest": "8.4.2",
    "referencing": "0.37.0",
    "rpds-py": "2026.6.3",
    "typing-extensions": "4.16.0",
}


def normalize(name: str) -> str:
    return name.casefold().replace("_", "-").replace(".", "-")


def main() -> int:
    if sys.version_info[:2] != (3, 12) or sys.version_info[:3] != (3, 12, 14):
        print(
            f"Python 3.12.14 required, found {sys.version.split()[0]}",
            file=sys.stderr,
        )
        return 2
    actual_packages = {
        normalize(distribution.metadata["Name"])
        for distribution in distributions()
        if distribution.metadata.get("Name")
    }
    expected_packages = {normalize(package) for package in EXACT_ENVIRONMENT}
    if actual_packages != expected_packages:
        print(
            "offline package set differs from the exact lock: "
            f"actual={sorted(actual_packages)} expected={sorted(expected_packages)}",
            file=sys.stderr,
        )
        return 2
    for package, wanted in EXACT_ENVIRONMENT.items():
        found = version(package)
        if found != wanted:
            print(f"{package}=={wanted} required, found {found}", file=sys.stderr)
            return 2
    print("offline toolchain validation passed: Python 3.12.14, 12 exact packages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
