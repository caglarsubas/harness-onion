from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "harness_reference_observe",
    ROOT / "reference-observer/harness-reference-observe.py",
)
assert SPEC and SPEC.loader
OBSERVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBSERVER)


def record(mode: str, object_type: str, object_id: str, path: str) -> bytes:
    return f"{mode} {object_type} {object_id}\t{path}\0".encode()


def test_git_tree_traversal_is_canonicalized_by_path() -> None:
    raw = b"".join(
        [
            record("040000", "tree", "b" * 40, "src"),
            record("100644", "blob", "c" * 40, "src/main.py"),
            record("100644", "blob", "a" * 40, "README.md"),
        ]
    )
    assert [item["path"] for item in OBSERVER._parse_tracked_tree(raw)] == [
        "README.md",
        "src",
        "src/main.py",
    ]


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        record("100644", "blob", "a" * 40, "../escape"),
        record("100644", "blob", "a" * 40, "same")
        + record("100644", "blob", "b" * 40, "same"),
        b"malformed\0",
    ],
)
def test_git_tree_parser_rejects_empty_unsafe_duplicate_or_malformed(raw: bytes) -> None:
    with pytest.raises(OBSERVER.LauncherError):
        OBSERVER._parse_tracked_tree(raw)
