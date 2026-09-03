#!/usr/bin/env python3
"""Root-owned launcher for exact-commit, non-copying reference observations."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


AUTHORITY_PATH = Path("/etc/planeon/reference-source-authority.json")
SIGNATURE_PATH = Path("/etc/planeon/reference-source-authority.json.sig")
PUBLIC_KEY_PATH = Path("/etc/planeon/reference-source-authority.pub")
OPENSSL = "/opt/homebrew/bin/openssl"
EXTRACTOR_PATH = Path("/opt/planeon/libexec/harness-reference-extract")
PROHIBITED_REPORT_KEYS = {
    "$comment", "description", "example", "examples", "raw", "sourceRoot",
    "sourceText", "title",
}
SCHEMA_FACT_KINDS = {
    "SCHEMA_IDENTITY", "OBJECT_FIELD", "REQUIRED_FIELD", "VALUE_CONSTRAINT",
    "STATE_ENUM", "REFERENCE_EDGE", "SCHEMA_DIGEST",
}
TREE_FACT_KINDS = {"REPOSITORY_SUMMARY", "TREE_ENTRY"}


class LauncherError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _verify_root_file(path: Path, mode: int) -> None:
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != mode:
        raise LauncherError(f"root-owned authority mode mismatch: {path.name}")


def _run(argv: list[str], *, cwd: Path | None = None, text: bool = True) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(argv, cwd=cwd, check=False, capture_output=True, text=text, shell=False)


def _verify_signature() -> None:
    for path, mode in ((AUTHORITY_PATH, 0o400), (SIGNATURE_PATH, 0o444), (PUBLIC_KEY_PATH, 0o444)):
        _verify_root_file(path, mode)
    result = _run([
        OPENSSL, "pkeyutl", "-verify", "-pubin", "-inkey", str(PUBLIC_KEY_PATH),
        "-sigfile", str(SIGNATURE_PATH), "-rawin", "-in", str(AUTHORITY_PATH),
    ])
    if result.returncode != 0:
        raise LauncherError("reference source authority signature verification failed")


def _load_inline_json_field(packet_text: str, field: str) -> Any:
    prefix = f"{field}:"
    matches = [line[len(prefix):].strip() for line in packet_text.splitlines() if line.startswith(prefix)]
    if len(matches) != 1:
        raise LauncherError(f"packet must contain one inline {field}")
    try:
        return json.loads(matches[0])
    except json.JSONDecodeError as exc:
        raise LauncherError(f"packet {field} is not canonical inline JSON") from exc


def _resolve_inside(root: Path, relative: str) -> Path:
    if not relative or relative.startswith("/") or ".." in Path(relative).parts:
        raise LauncherError("authority contains unsafe repository-relative path")
    resolved = root.joinpath(*relative.split("/")).resolve(strict=True)
    if resolved != root and root not in resolved.parents:
        raise LauncherError("authority path escapes its root")
    return resolved


def _sandbox_literal(path: Path) -> str:
    return '"' + str(path).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _sandbox_profile(source_root: Path, source_paths: list[str]) -> str:
    data_rules = " ".join(
        f"(literal {_sandbox_literal(_resolve_inside(source_root, relative))})"
        for relative in sorted(source_paths)
    )
    rules = [
        "(version 1)", "(allow default)", "(deny network*)", "(deny file-write*)",
        f"(deny file-read* (subpath {_sandbox_literal(source_root)}))",
        f"(deny process-exec (subpath {_sandbox_literal(source_root)}))",
    ]
    if data_rules:
        rules.append(f"(allow file-read* {data_rules})")
    return "\n".join(rules)


def _drop_to_observer(uid: int, gid: int) -> None:
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)


def _parse_tracked_tree(raw: bytes) -> list[dict[str, str]]:
    """Parse and canonicalize Git's traversal-ordered recursive tree output."""

    bindings: list[dict[str, str]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, separator, raw_path = record.partition(b"\t")
        if not separator:
            raise LauncherError("git tree record is malformed")
        try:
            mode, object_type, git_object = metadata.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise LauncherError("git tree record is not canonical UTF-8 metadata") from exc
        if object_type not in {"blob", "tree", "commit"} or not path or path.startswith("/") or ".." in Path(path).parts:
            raise LauncherError("git tree record contains an unsafe entry")
        bindings.append({"path": path, "mode": mode, "objectType": object_type, "gitObject": git_object})
    bindings.sort(key=lambda item: item["path"])
    if not bindings or len({item["path"] for item in bindings}) != len(bindings):
        raise LauncherError("git tree inventory is empty or contains duplicate paths")
    return bindings


def _tracked_tree(source_root: Path) -> list[dict[str, str]]:
    result = _run(
        ["/usr/bin/git", "-C", str(source_root), "ls-tree", "-r", "-t", "--full-tree", "-z", "HEAD"],
        text=False,
    )
    if result.returncode != 0:
        raise LauncherError("cannot enumerate the pinned tracked tree")
    return _parse_tracked_tree(result.stdout)


def _check_report(report: dict[str, Any], authority: dict[str, Any], raw: bytes) -> None:
    if str(authority["sourceRoot"]).encode("utf-8") in raw:
        raise LauncherError("distilled report leaked the warm-source root")

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            overlap = PROHIBITED_REPORT_KEYS & set(value)
            if overlap:
                raise LauncherError(f"distilled report contains prohibited key {sorted(overlap)[0]}")
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(report)
    if report.get("schemaVersion") != "harness.planeon.ai/reference-observation/v1":
        raise LauncherError("distilled report schema version mismatch")
    facts = report.get("facts")
    sources = report.get("sources")
    if not isinstance(facts, list) or not facts or not isinstance(sources, list):
        raise LauncherError("distilled report is incomplete")
    mode = authority["packetObservation"].get("observationMode")
    allowed_kinds = TREE_FACT_KINDS if mode == "FULL_TRACKED_TREE_METADATA" else SCHEMA_FACT_KINDS
    if any(not isinstance(fact, dict) or fact.get("kind") not in allowed_kinds for fact in facts):
        raise LauncherError("distilled report contains an undeclared fact kind")
    if facts != sorted(facts, key=_canonical_json):
        raise LauncherError("distilled report facts are not canonical")
    expected_bindings = authority["sourceBindings"]
    if mode == "FULL_TRACKED_TREE_METADATA":
        if sources != expected_bindings:
            raise LauncherError("distilled tree report differs from signed bindings")
    elif [item.get("path") for item in sources] != sorted(item["path"] for item in expected_bindings):
        raise LauncherError("distilled schema report source set differs from signed bindings")


def main() -> int:
    if os.geteuid() != 0:
        raise LauncherError("reference observer launcher must run as root")
    _verify_root_file(Path(__file__).resolve(), 0o555)
    _verify_root_file(EXTRACTOR_PATH, 0o555)
    _verify_signature()
    authority = json.loads(AUTHORITY_PATH.read_text(encoding="utf-8"))
    required_keys = {
        "schemaVersion", "authorityId", "launcherSha256", "extractorSha256",
        "packetId", "packetDigest", "packetObservation", "repository", "commit",
        "sourceRoot", "sourceBindings", "observerIdentity", "observerUid",
        "observerGid", "issuedAt",
    }
    if set(authority) != required_keys or authority["schemaVersion"] != "harness.planeon.ai/reference-source-authority/v1":
        raise LauncherError("reference source authority has unknown members or wrong version")
    if authority["launcherSha256"] != _sha256(Path(__file__).resolve()) or authority["extractorSha256"] != _sha256(EXTRACTOR_PATH):
        raise LauncherError("reference observer artifact digest mismatch")
    if os.environ.get("HARNESS_REFERENCE_SOURCE_AUTHORITY") != str(AUTHORITY_PATH):
        raise LauncherError("signed source authority environment is missing or widened")

    workspace = Path(os.environ.get("GITHUB_WORKSPACE", "")).resolve(strict=True)
    packet_path = Path(os.environ.get("HARNESS_TASK_PACKET", "")).resolve(strict=True)
    expected_packet = (workspace / f"task-packets/{authority['packetId']}.yaml").resolve(strict=True)
    if packet_path != expected_packet:
        raise LauncherError("packet path is not the signed workspace authority")
    packet_bytes = packet_path.read_bytes()
    if hashlib.sha256(packet_bytes).hexdigest() != authority["packetDigest"]:
        raise LauncherError("observation packet digest mismatch")
    if _load_inline_json_field(packet_bytes.decode("utf-8"), "referenceObservationExecution") != authority["packetObservation"]:
        raise LauncherError("packet observation binding differs from signed source authority")

    source_root = Path(authority["sourceRoot"]).resolve(strict=True)
    head = _run(["/usr/bin/git", "-C", str(source_root), "rev-parse", "HEAD"])
    symbolic = _run(["/usr/bin/git", "-C", str(source_root), "symbolic-ref", "-q", "HEAD"])
    dirty = _run(["/usr/bin/git", "-C", str(source_root), "status", "--porcelain=v1", "--untracked-files=all"])
    if head.returncode != 0 or head.stdout.strip() != authority["commit"] or symbolic.returncode == 0 or dirty.returncode != 0 or dirty.stdout:
        raise LauncherError("source snapshot is not exact, detached, and clean")

    observation = authority["packetObservation"]
    if observation.get("observationMode") == "FULL_TRACKED_TREE_METADATA":
        if authority["sourceBindings"] != _tracked_tree(source_root):
            raise LauncherError("signed full-tree bindings differ from the exact commit")
        source_paths: list[str] = []
    else:
        source_paths = [binding["path"] for binding in authority["sourceBindings"]]
        if source_paths != observation["sourcePaths"]:
            raise LauncherError("signed source bindings differ from packet path order")
        for binding in authority["sourceBindings"]:
            path = _resolve_inside(source_root, binding["path"])
            metadata = path.stat()
            if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o222:
                raise LauncherError("declared source blob is not regular and write-bit-free")
            object_result = _run(["/usr/bin/git", "-C", str(source_root), "rev-parse", f"HEAD:{binding['path']}"])
            if object_result.returncode != 0 or object_result.stdout.strip() != binding["gitObject"]:
                raise LauncherError("declared source Git object mismatch")

    observer = pwd.getpwnam("nobody")
    if authority["observerIdentity"] != "planeon-reference-observer" or authority["observerUid"] != observer.pw_uid or authority["observerGid"] != observer.pw_gid:
        raise LauncherError("separate observer identity binding mismatch")
    profile = _sandbox_profile(source_root, source_paths)
    completed = subprocess.run(
        ["/usr/bin/sandbox-exec", "-p", profile, "/usr/bin/python3", str(EXTRACTOR_PATH)],
        input=_canonical_json(authority), text=True, capture_output=True, check=False,
        shell=False, env={
            "HOME": "/private/var/empty", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "PYTHONDONTWRITEBYTECODE": "1",
        }, preexec_fn=lambda: _drop_to_observer(observer.pw_uid, observer.pw_gid),
    )
    if completed.returncode != 0:
        reason = completed.stderr.strip().splitlines()[-1] if completed.stderr.strip() else "no diagnostic"
        raise LauncherError(f"sandboxed reference extraction failed with return code {completed.returncode}: {reason}")
    raw = completed.stdout.encode("utf-8")
    report = json.loads(raw)
    _check_report(report, authority, raw)
    canonical_output = (json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    output_path = workspace / observation["outputPath"]
    if output_path.exists() and output_path.read_bytes() != canonical_output:
        raise LauncherError("existing observation output differs from deterministic result")
    if not output_path.exists():
        output_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = output_path.with_suffix(output_path.suffix + ".tmp")
        temporary.write_bytes(canonical_output)
        os.chmod(temporary, 0o644)
        os.chown(temporary, int(os.environ.get("SUDO_UID", "0")), int(os.environ.get("SUDO_GID", "0")))
        os.replace(temporary, output_path)
    print(
        f"reference observation passed: packet={authority['packetDigest']} "
        f"sources={len(report['sources'])} facts={len(report['facts'])} "
        f"outputSha256={hashlib.sha256(canonical_output).hexdigest()}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (LauncherError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"reference observation blocked: {exc}", file=sys.stderr)
        raise SystemExit(1)
