"""Pinned PyYAML safe construction with its optional installed native parser.

No global monkeypatch, parsed-object cache, result reuse, environment selector or
download. Each call constructs fresh objects; callers keep their own stricter
mapping constructors. The pure-Python parser remains the portability fallback.
"""
from __future__ import annotations

import yaml


def _select_safe_loader():
    return getattr(yaml, "CSafeLoader", yaml.SafeLoader)


SafeLoader = _select_safe_loader()


def safe_load(stream):
    return yaml.load(stream, Loader=SafeLoader)
