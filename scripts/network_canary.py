#!/usr/bin/env python3
"""Fail unless an OS-level network boundary blocks an outbound connection."""

from __future__ import annotations

import errno
import os
import socket
import sys

backend = os.environ.get("HARNESS_OFFLINE_BACKEND", "")
expected_errors = {
    "darwin-sandbox": {errno.EACCES, errno.EPERM},
    "linux-netns": {errno.EACCES, errno.EPERM, errno.ENETUNREACH, errno.EHOSTUNREACH},
    "linux-firejail": {errno.EACCES, errno.EPERM, errno.ENETUNREACH, errno.EHOSTUNREACH},
}.get(backend)

if not expected_errors:
    print("network canary refused: no recognized OS isolation backend", file=sys.stderr)
    raise SystemExit(2)

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(0.5)
        result = client.connect_ex(("1.1.1.1", 443))
except OSError as exc:
    result = exc.errno

if result not in expected_errors:
    print(
        f"network canary failed: backend={backend} returned errno={result}; "
        "OS-level egress denial was not proven",
        file=sys.stderr,
    )
    raise SystemExit(1)

print(f"network canary passed: {backend} denied outbound egress with errno={result}")
