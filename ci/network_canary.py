#!/usr/bin/env python3
"""Fail if an outbound TCP connection succeeds inside the offline sandbox."""

from __future__ import annotations

import socket


def main() -> int:
    try:
        with socket.create_connection(("1.1.1.1", 443), timeout=0.5):
            pass
    except OSError:
        print("offline network canary: outbound connection denied")
        return 0
    print("offline network canary: outbound connection unexpectedly succeeded")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
