"""Fixed read-only Linux isolation negatives, before any repository code.

No real warm-source contents are read or modified, even if a denial fails.
Synthetic tests of these functions are never host qualification records.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys

from common import PACKET, PROOFS, PYTHON, Refused, canonical, digest, require

STRICT_DENIAL = {errno.EACCES, errno.EPERM}
HIDDEN_DENIAL = STRICT_DENIAL | {errno.ENOENT}
NETWORK_CASES = ("IPV4_TCP", "IPV6_TCP", "IPV4_UDP_DNS", "IPV6_UDP_DNS",
                 "LOOPBACK_IPV4", "LOOPBACK_IPV6", "UNIX_PATH", "UNIX_ABSTRACT")


def denied(operation, allowed):
    try:
        value = operation()
    except OSError as exc:
        return exc.errno in allowed
    else:
        if type(value) is int:
            os.close(value)
        return False


def network_negatives():
    # Deny socket creation at seccomp: never send even one probe packet. Neither
    # timeout, DNS failure, connection refusal nor an absent route is accepted.
    families = (socket.AF_INET, socket.AF_INET6, socket.AF_INET, socket.AF_INET6,
                socket.AF_INET, socket.AF_INET6, socket.AF_UNIX, socket.AF_UNIX)
    types = (socket.SOCK_STREAM, socket.SOCK_STREAM, socket.SOCK_DGRAM, socket.SOCK_DGRAM,
             socket.SOCK_STREAM, socket.SOCK_STREAM, socket.SOCK_STREAM, socket.SOCK_DGRAM)
    result = {}
    for name, family, kind in zip(NETWORK_CASES, families, types, strict=True):
        try:
            s = socket.socket(family, kind)
        except OSError as exc:
            result[name] = exc.errno in STRICT_DENIAL
        else:
            s.close()
            result[name] = False
    return result


def hidden(path):
    # Opening the root directory is enough; do not enumerate or open its files.
    return {
        "read": denied(lambda: os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), HIDDEN_DENIAL),
        "metadata": denied(lambda: os.lstat(path), HIDDEN_DENIAL),
        "write": denied(lambda: os.open(path, os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW), HIDDEN_DENIAL),
    }


def kernel_boundary(parent_namespaces):
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    require(status.get("NoNewPrivs", "").strip() == "1" and status.get("Seccomp", "").strip() == "2"
            and int(status.get("CapEff", "1").strip(), 16) == 0, "kernel restrictions missing")
    for namespace in ("net", "mnt", "pid"):
        require(os.readlink("/proc/self/ns/" + namespace) != parent_namespaces[namespace], "namespace not isolated")
    require(os.geteuid() != 0, "repository identity is root")


def assert_no_sensitive_environment(environment, roots):
    allowed = {"PATH", "HOME", "TMPDIR", "USER", "LOGNAME", "LANG", "LC_ALL", "PYTHONDONTWRITEBYTECODE",
               "UV_OFFLINE", "UV_FROZEN", "UV_NO_SYNC", "UV_PYTHON_DOWNLOADS", "NEXT_TELEMETRY_DISABLED",
               "NPM_CONFIG_OFFLINE", "NPM_CONFIG_AUDIT", "NPM_CONFIG_FUND", "NPM_CONFIG_UPDATE_NOTIFIER",
               "CI", "GITHUB_ACTIONS", "GITHUB_WORKSPACE", "GITHUB_SHA", "GITHUB_REPOSITORY",
               "HARNESS_OFFLINE_ENFORCED", "HARNESS_OFFLINE_BACKEND", "HARNESS_OFFLINE_SESSION_ID"}
    require(set(environment) <= allowed and not any(root in value for root in roots for value in environment.values()),
            "protected or unknown child environment")


def run(context, *, descendants=True):
    kernel_boundary(context["parentNamespaces"])
    assert_no_sensitive_environment(dict(os.environ), context["roots"])
    network = network_negatives()
    require(all(network.values()), "socket syscall denial not proven")
    paths = context["roots"] + context["hiddenPaths"]
    findings = [hidden(path) for path in paths]
    require(all(all(row.values()) for row in findings), "read/metadata/write path denial failed")
    require(denied(lambda: os.open(PACKET, os.O_WRONLY | os.O_NOFOLLOW), {errno.EROFS, errno.EACCES, errno.EPERM}),
            "packet write not denied")
    # Parent launcher argv contains only a fixed profile path, never warm roots.
    # /proc must not expose a process outside this PID namespace or root inventory.
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            try:
                cmdline = (entry / "cmdline").read_bytes()
            except (FileNotFoundError, PermissionError):
                continue
            require(not any(root.encode() in cmdline for root in context["roots"]), "warm roots leaked through proc argv")
    if descendants:
        # A new interpreter proves inherited filters, not a monkeypatched socket.
        result = subprocess.run([PYTHON, "-IB", context["launcher"], "--probe-child"],
                                input=canonical(context), capture_output=True, close_fds=True, timeout=20)
        require(result.returncode == 0 and result.stdout.strip() == b'CHILD_NEGATIVES_PASS', "descendant isolation failed")
    return {"status": "PASS", "scope": "HOST_ISOLATION_ONLY", "networkCases": network,
            "hiddenPathCount": len(paths), "descendantsChecked": descendants,
            **{name: True for name in PROOFS}}


def installed_availability():
    """No install, discovery or network fallback; real probes need external custody."""
    import platform
    from common import ANCHOR, LAUNCHER
    if platform.system() != "Linux":
        return {"status": "NOT_RUN_ENV_UNAVAILABLE", "reason": "NON_LINUX_HOST", "nativeLinuxAcceptance": False}
    if not Path(ANCHOR).is_file() or not Path(LAUNCHER).is_file():
        return {"status": "NOT_RUN_ENV_UNAVAILABLE", "reason": "SIGNED_LINUX_INSTALLATION_ABSENT", "nativeLinuxAcceptance": False}
    return None
