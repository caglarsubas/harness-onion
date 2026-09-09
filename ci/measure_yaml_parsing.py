"""Fixed local data-only parser comparison; not source or runtime acceptance."""
from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path
import stat
import time

import yaml

ROOT = Path(__file__).resolve().parents[1]


def shape(value):
    """Compare types, values, order, alias identity and cycles, not only equality."""
    seen = {}

    def visit(item):
        kind = type(item).__name__
        if type(item) in (dict, list, tuple, set):
            identity = id(item)
            if identity in seen:
                return ["reference", seen[identity]]
            number = len(seen)
            seen[identity] = number
            if type(item) is dict:
                values = [[visit(k), visit(v)] for k, v in item.items()]
            elif type(item) is set:
                values = sorted((visit(v) for v in item), key=repr)
            else:
                values = [visit(v) for v in item]
            return [kind, number, values]
        if type(item) is bytes:
            return [kind, item.hex()]
        if type(item) is float:
            return [kind, item.hex()]
        if isinstance(item, (datetime.datetime, datetime.date)):
            return [kind, item.isoformat()]
        if type(item) in (str, int, bool, type(None)):
            return [kind, item]
        raise TypeError("unsupported comparison type: " + kind)

    return visit(value)


def main():
    accelerated = getattr(yaml, "CSafeLoader", None)
    if accelerated is None:
        print('YAML_PARSER_MEASUREMENT={"status":"NOT_RUN_ENV_UNAVAILABLE","reason":"PINNED_LIBYAML_ABSENT"}')
        return 1
    paths = sorted({p for folder in ("architecture", "legal", "policies", "release", "task-packets")
                    for p in (ROOT / folder).rglob("*.yaml")})
    rows = []
    for path in paths:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 8 * 1024 * 1024:
            raise ValueError("nonregular or oversized measurement input")
        raw = path.read_bytes()
        durations = []
        outputs = []
        for loader in (yaml.SafeLoader, accelerated):
            start = time.perf_counter_ns()
            result = yaml.load(raw, Loader=loader)
            durations.append(time.perf_counter_ns() - start)
            outputs.append(shape(result))
        if outputs[0] != outputs[1]:
            raise ValueError("parser semantics differ: " + str(path.relative_to(ROOT)))
        rows.append({"path": str(path.relative_to(ROOT)), "sha256": hashlib.sha256(raw).hexdigest(),
                     "bytes": len(raw), "pythonNs": durations[0], "libyamlNs": durations[1]})
    pure = sum(row["pythonNs"] for row in rows)
    fast = sum(row["libyamlNs"] for row in rows)
    print("YAML_PARSER_MEASUREMENT=" + json.dumps({
        "status": "MEASURED", "evidence": "DATA_ONLY_NOT_ACCEPTANCE", "pyyamlVersion": yaml.__version__,
        "fileCount": len(rows), "bytes": sum(row["bytes"] for row in rows),
        "pythonNs": pure, "libyamlNs": fast, "ratio": pure / max(fast, 1),
        "semanticParity": "TYPES_VALUES_ORDER_ALIASES_CYCLES_EQUAL", "rows": rows,
    }, sort_keys=True, separators=(",", ":")), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
