"""Replay MET-LIVE-003's vectors with no repository reads: the model, binding.json, vectors.json and the v1/ files
from this folder, and LPK-0's adopted record from the path given. Exits 1 on any mismatch.
Usage: python3 -I -B replay.py <folder holding linux_probe_interface.py, binding.json, vectors.json, v1/> <LPK-0 amendment.json>"""
import copy, importlib.machinery, importlib.util, json, sys



def apply(document, ops):
    document = copy.deepcopy(document)
    for op in ops:
        parts = [p.replace("~1", "/").replace("~0", "~") for p in op["path"].split("/")[1:]]
        node = document
        for part in parts[:-1]:
            node = node[int(part)] if isinstance(node, list) else node[part]
        key = parts[-1] if parts else None
        key = int(key) if isinstance(node, list) and key not in (None, "-") else key
        if op["op"] == "set" and not parts:
            document = op["value"]
        elif op["op"] == "set":
            node[key] = op["value"]
        elif op["op"] == "delete":
            del node[key]
        elif op["op"] == "append":
            node.append(op["value"])
    return document


def files_for(base, overrides):
    """The v1/ files with a vector's overrides: JSON pointer ops, raw text, or a deeply nested array."""
    out = dict(base)
    for name, change in overrides.items():
        if "ops" in change:
            out[name] = json.dumps(apply(json.loads(base[name]), change["ops"]), ensure_ascii=False).encode("utf-8")
        elif "text" in change:
            out[name] = change["text"].encode("utf-8")
        elif "nestedArray" in change:
            out[name] = ("[" * change["nestedArray"] + "]" * change["nestedArray"]).encode()
    return out


def reader(m, files, lpk0):
    def read(path):
        if path.startswith(m.DIRECTORY):
            return files.get(path[len(m.DIRECTORY):])
        if path == m.LPK0_RECORD:
            return lpk0
        return None
    return read


def main(folder, lpk0_path):
    spec = importlib.util.spec_from_loader("m", importlib.machinery.SourceFileLoader("m", folder + "/linux_probe_interface.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    record = json.load(open(folder + "/binding.json"))
    vectors = json.load(open(folder + "/vectors.json"))
    base = {name: open(folder + "/v1/" + name, "rb").read() for name in m.FILES}
    lpk0 = open(lpk0_path, "rb").read()
    return run(m, record, vectors, base, lpk0)


def run(m, record, vectors, base, lpk0):
    bad = []
    got = m.check(record, reader(m, base, lpk0))
    if got != vectors["positive"]["refusals"]:
        bad.append(("positive", got))
    for vector in vectors["negatives"]:
        got = m.check(apply(record, vector["recordOps"]), reader(m, files_for(base, vector["fileOverrides"]), lpk0))
        if got != vector["refusals"]:
            bad.append((vector["label"], got))
    instance, schema = json.loads(base["probe-interface.json"]), json.loads(base["probe-interface.schema.json"])
    for vector in vectors["validatorVectors"]:
        i = apply(instance, vector["instanceOps"])
        s = apply(schema, vector["schemaOps"])
        if m.valid(i, s, s) != vector["valid"]:
            bad.append((vector["label"], not vector["valid"]))
    return {"positive": 1, "negatives": len(vectors["negatives"]), "validatorVectors": len(vectors["validatorVectors"]),
            "mismatches": bad}


if __name__ == "__main__":
    result = main(sys.argv[1], sys.argv[2])
    print(json.dumps(result, indent=1))
    sys.exit(1 if result["mismatches"] else 0)
