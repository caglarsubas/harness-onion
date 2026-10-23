"""Replay LPK-0's vectors: the model, amendment.json and vectors.json from a candidate folder, and the base bytes from
`git show 2043cc27:<path>` in the harness-onion checkout given (read-only, recorded paths only). Exits 1 on any mismatch.
Usage: python3 -I -B replay.py <candidate folder> <harness-onion checkout>"""
import copy, importlib.machinery, importlib.util, json, subprocess, sys

FOLDER, REPO = sys.argv[1:3]
spec = importlib.util.spec_from_loader("m", importlib.machinery.SourceFileLoader("m", FOLDER + "/probe_kit_scope.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
record = json.load(open(FOLDER + "/amendment.json"))
vectors = json.load(open(FOLDER + "/vectors.json"))
ENV = {"GIT_OPTIONAL_LOCKS": "0", "PATH": "/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin", "LC_ALL": "C"}
cache = {}


def read(path):
    if path not in cache:
        out = subprocess.run(["git", "-C", REPO, "show", "%s:%s" % (m.BASE, path)], capture_output=True, env=ENV)
        cache[path] = out.stdout if out.returncode == 0 else None
    return cache[path]


def apply(document, ops):
    document = copy.deepcopy(document)
    for op in ops:
        parts = [p.replace("~1", "/").replace("~0", "~") for p in op["path"].split("/")[1:]]
        node = document
        for part in parts[:-1]:
            node = node[int(part)] if isinstance(node, list) else node[part]
        last = parts[-1]
        key = int(last) if isinstance(node, list) and last != "-" else last
        if op["op"] == "set":
            node[key] = op["value"]
        elif op["op"] == "delete":
            del node[key]
        elif op["op"] == "append":
            node.append(op["value"])
    return document


bad = []
positive = vectors["positive"]
got = m.check(record, read, positive["changedFiles"], positive["gatePaths"])
if got != positive["refusals"]:
    bad.append(("positive", got))
for vector in vectors["negatives"]:
    got = m.check(apply(record, vector["mutations"]), read, vector["changedFiles"], vector["gatePaths"])
    if vector["refusal"] not in got:
        bad.append((vector["label"], got))
print(json.dumps({"positive": 1, "negatives": len(vectors["negatives"]), "mismatches": bad}, indent=1))
sys.exit(1 if bad else 0)
