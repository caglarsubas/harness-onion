#!/usr/bin/env python3
"""Lock or verify an exact warm-source snapshot without using a shell."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
NO_FETCH_REMOTE = "no-fetch://immutable-warm-source"
NO_PUSH_REMOTE = "no-push://immutable-warm-source"


class SnapshotError(RuntimeError):
    """The source snapshot cannot satisfy the immutable-reference contract."""


class UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that refuses an ambiguous duplicate authority key."""


def _construct_unique_mapping(
    loader: UniqueKeySafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise SnapshotError(
                f"duplicate reuse-index key {key!r} at line {key_node.start_mark.line + 1}"
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def git_environment() -> dict[str, str]:
    """Return a non-interactive Git environment without ambient credentials."""

    return {
        "PATH": os.environ.get("PATH", os.defpath),
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "never",
        "LANG": "C",
        "LC_ALL": "C",
    }


def run_git(snapshot: Path, arguments: list[str], *, input_text: str | None = None) -> str:
    completed = subprocess.run(
        ["git", "-C", str(snapshot), *arguments],
        input=input_text,
        text=True,
        capture_output=True,
        env=git_environment(),
        shell=False,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise SnapshotError(f"git {' '.join(arguments)} failed: {detail}")
    return completed.stdout


def load_index(repository: str) -> tuple[str, list[dict[str, Any]]]:
    authority = yaml.load(
        (ROOT / "architecture/reuse-path-index.yaml").read_text(encoding="utf-8"),
        Loader=UniqueKeySafeLoader,
    )
    matches = [
        source
        for source in authority.get("sources", [])
        if source.get("repository") == repository
    ]
    if len(matches) != 1:
        raise SnapshotError("repository must occur exactly once in the reuse index")
    source = matches[0]
    return str(source["commit"]), list(source.get("paths", []))


def parse_tree(snapshot: Path, commit: str) -> dict[str, tuple[str, str]]:
    output = run_git(
        snapshot,
        ["ls-tree", "-r", "-t", "-z", "--full-tree", commit],
    )
    objects: dict[str, tuple[str, str]] = {}
    for record in output.split("\0"):
        if not record:
            continue
        metadata, path = record.split("\t", 1)
        _mode, kind, object_id = metadata.split(" ", 2)
        objects[path] = (kind, object_id)
    return objects


def verify_local_objects(snapshot: Path, entries: list[dict[str, Any]]) -> None:
    """Require each indexed object to be present locally with its indexed Git kind."""

    expected_by_object: dict[str, str] = {}
    indexed_paths: set[str] = set()
    for entry in entries:
        indexed_path = str(entry["path"])
        if indexed_path in indexed_paths:
            raise SnapshotError(f"indexed path is duplicated: {indexed_path}")
        indexed_paths.add(indexed_path)
        object_id = str(entry["gitObject"])
        kind = str(entry["kind"])
        prior_kind = expected_by_object.setdefault(object_id, kind)
        if prior_kind != kind:
            raise SnapshotError(
                f"indexed object {object_id} has conflicting kinds: {prior_kind}, {kind}"
            )

    object_ids = sorted(expected_by_object)
    batch = run_git(
        snapshot,
        ["cat-file", "--batch-check=%(objectname) %(objecttype)"],
        input_text="".join(f"{object_id}\n" for object_id in object_ids),
    )
    lines = batch.splitlines()
    if len(lines) != len(object_ids):
        raise SnapshotError("not every indexed object returned a local object record")
    for object_id, line in zip(object_ids, lines, strict=True):
        expected = f"{object_id} {expected_by_object[object_id]}"
        if line != expected:
            raise SnapshotError(
                f"indexed object is missing or has the wrong kind: expected={expected!r}, actual={line!r}"
            )


def verify_snapshot(
    snapshot: Path,
    repository: str,
    commit: str,
    entries: list[dict[str, Any]],
    *,
    require_locked: bool,
) -> dict[str, Any]:
    if snapshot.is_symlink():
        raise SnapshotError("snapshot root must not be a symbolic link")
    resolved = snapshot.resolve(strict=True)
    forbidden_roots = {Path.home().resolve(), ROOT.resolve()}
    if (
        resolved == Path("/")
        or any(
            resolved == forbidden
            or forbidden in resolved.parents
            or resolved in forbidden.parents
            for forbidden in forbidden_roots
        )
        or not (resolved / ".git").is_dir()
        or (resolved / ".git").is_symlink()
    ):
        raise SnapshotError("snapshot must be a dedicated Git working tree")
    alternates = resolved / ".git/objects/info/alternates"
    if alternates.exists():
        raise SnapshotError("snapshot object store must not use alternates")
    run_git(resolved, ["cat-file", "-e", f"{commit}^{{commit}}"])
    if run_git(resolved, ["rev-parse", "HEAD"]).strip() != commit:
        raise SnapshotError("snapshot HEAD differs from the indexed commit")
    symbolic = subprocess.run(
        ["git", "-C", str(resolved), "symbolic-ref", "-q", "HEAD"],
        text=True,
        capture_output=True,
        env=git_environment(),
        shell=False,
        check=False,
    )
    if symbolic.returncode == 0:
        raise SnapshotError("snapshot HEAD must be detached")
    if symbolic.returncode not in {1}:
        raise SnapshotError("unable to prove detached HEAD")
    if run_git(
        resolved,
        [
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=matching",
        ],
    ):
        raise SnapshotError("snapshot working tree is not clean")

    tree = parse_tree(resolved, commit)
    inventory: list[str] = []
    for entry in entries:
        indexed_path = str(entry["path"])
        path = indexed_path.rstrip("/")
        actual = tree.get(path)
        expected = (str(entry["kind"]), str(entry["gitObject"]))
        if actual != expected:
            raise SnapshotError(
                f"indexed path mismatch for {indexed_path}: expected={expected}, actual={actual}"
            )
        inventory.append(f"{expected[0]} {expected[1]} {indexed_path}")

    verify_local_objects(resolved, entries)

    if require_locked:
        remotes = run_git(resolved, ["remote"]).splitlines()
        if remotes != ["origin"]:
            raise SnapshotError("snapshot must contain only the disabled origin remote")
        if run_git(resolved, ["remote", "get-url", "origin"]).strip() != NO_FETCH_REMOTE:
            raise SnapshotError("fetch remote is not disabled")
        if (
            run_git(resolved, ["remote", "get-url", "--push", "origin"]).strip()
            != NO_PUSH_REMOTE
        ):
            raise SnapshotError("push remote is not disabled")
        writable = []
        for path in [resolved, *resolved.rglob("*")]:
            if path.is_symlink():
                continue
            if stat.S_IMODE(path.stat().st_mode) & 0o222:
                writable.append(str(path.relative_to(resolved)) or ".")
                if len(writable) == 5:
                    break
        if writable:
            raise SnapshotError(f"snapshot contains writable paths: {writable}")

    return {
        "repository": repository,
        "commit": commit,
        "indexedPathCount": len(entries),
        "inventorySha256": hashlib.sha256(
            "\n".join(sorted(inventory)).encode("utf-8")
        ).hexdigest(),
        "detached": True,
        "clean": True,
        "objectsLocal": True,
        "objectAlternatesDisabled": True,
        "writeBitsRemoved": require_locked,
        "fetchDisabled": require_locked,
        "pushDisabled": require_locked,
        "ambientCredentialsScrubbed": True,
    }


def remove_write_bits(snapshot: Path) -> None:
    paths = [path for path in snapshot.rglob("*") if not path.is_symlink()]
    paths.sort(key=lambda path: len(path.parts), reverse=True)
    for path in [*paths, snapshot]:
        mode = stat.S_IMODE(path.stat().st_mode)
        os.chmod(path, mode & ~0o222)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("lock", "verify"))
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    commit, entries = load_index(arguments.repository)
    verify_snapshot(
        arguments.snapshot,
        arguments.repository,
        commit,
        entries,
        require_locked=arguments.mode == "verify",
    )
    if arguments.mode == "lock":
        run_git(arguments.snapshot, ["remote", "set-url", "origin", NO_FETCH_REMOTE])
        run_git(
            arguments.snapshot,
            ["remote", "set-url", "--push", "origin", NO_PUSH_REMOTE],
        )
        remove_write_bits(arguments.snapshot.resolve())
    evidence = verify_snapshot(
        arguments.snapshot,
        arguments.repository,
        commit,
        entries,
        require_locked=True,
    )
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, SnapshotError, yaml.YAMLError) as exc:
        print(f"warm snapshot refused: {exc}", file=sys.stderr)
        raise SystemExit(2)
