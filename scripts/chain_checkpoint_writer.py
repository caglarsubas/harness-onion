"""MET-PERF-047 (CHAIN-COMPACTION-002): the checkpoint writer and its capture plugin. Lane-run only; never in the 64 argv.

usage: chain_checkpoint_writer.py run WORKTREE OUT_DIR          argv 63, run directly, with the capture plugin
       chain_checkpoint_writer.py assemble WORKTREE OUT_DIR SLOT [SIZE_BOUND]   the ledger from the capture shards
       chain_checkpoint_writer.py rehash WORKTREE RECORD        every attested digest re-hashed at the final commit

The writing run's stated difference (Q-282C-3): argv 1-62 and 64 run through ci/run_packet_argv.py as the dry run
runs them; argv 63 runs directly, the same command in the same interpreter, with `-p scripts.chain_checkpoint_writer`
and the two capture variables below. An option keeps the parallel suite serial, so the capture sees every node in one
process. The plugin observes only: it adds one audit hook on "open" and appends, per node and phase, the repository
paths opened for reading to its shard under OUT_DIR; it never writes inside the worktree and never changes a report,
an outcome or the exit status. The writer refuses an attested node (condition (i)), a failed full-run proof, an input
outside the repository and a ledger over SIZE_BOUND (it never truncates)."""
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

CAPTURE_ENV = ("CHAIN_CHECKPOINT_CAPTURE_DIR", "CHAIN_CHECKPOINT_CAPTURE_ROOT")
RECORD_PATH = "architecture/chain-checkpoint/record.json"
AUTHORITY_PATH = "architecture/chain-checkpoint-authority.json"
SCHEMA = "harness.planeon.ai/chain-checkpoint/v1"
ARGV63 = ["-m", "pytest", "tests", "ci/test_offline_runner.py", "ci/test_warm_snapshot.py"]
PARAMETERS = {"cadenceSlots": 10, "sampleFraction": 0.1, "fullRunOn": "owner-named slot", "nShadow": 10,
              "shadowCapSeconds": 15, "workers": 8}
SKIP_PARTS = (".git", "__pycache__", ".venv", ".pytest_cache")


class Refused(SystemExit):
    def __init__(self, message):
        super().__init__("chain checkpoint writer refused: %s" % message)


# ---- the capture plugin (loaded by -p in the writing run only) ----
_state = {"node": None, "phase": None, "opened": {}, "reports": [], "collected": 0}


def _audit(event, args):
    if event != "open" or _state["node"] is None or not args:
        return
    path, mode = args[0], args[1] if len(args) > 1 else "r"
    if not isinstance(path, (str, bytes)) or (isinstance(mode, str) and any(m in mode for m in "wax+")):
        return
    root = os.environ.get(CAPTURE_ENV[1])
    try:
        rel = os.path.relpath(os.path.realpath(os.fsdecode(path)), root)
    except (TypeError, ValueError):
        return
    if rel.startswith("..") or any(part in SKIP_PARTS for part in Path(rel).parts):
        return
    _state["opened"].setdefault(_state["node"], set()).add(Path(rel).as_posix())


def pytest_configure(config):
    if os.environ.get(CAPTURE_ENV[0]):
        import sys as _sys
        _sys.addaudithook(_audit)


def pytest_collection_finish(session):
    _state["collected"] = len(session.items)


def _phase(item, phase):
    _state["node"], _state["phase"] = item.nodeid, phase


def pytest_runtest_setup(item):
    _phase(item, "setup")


def pytest_runtest_call(item):
    _phase(item, "call")


def pytest_runtest_teardown(item):
    _phase(item, "teardown")


def pytest_runtest_logreport(report):
    _state["reports"].append([report.nodeid, report.when, report.outcome, round(report.duration, 4)])


def pytest_sessionfinish(session, exitstatus):
    out = os.environ.get(CAPTURE_ENV[0])
    if not out:
        return
    shard = Path(out) / ("shard-%d.json" % os.getpid())
    shard.write_text(json.dumps({"collected": _state["collected"], "reports": _state["reports"], "attested": [],
                                 "opened": {k: sorted(v) for k, v in _state["opened"].items()}}, sort_keys=True),
                     encoding="utf-8")


# ---- the writer ----
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def run(worktree, out_dir):
    out_dir.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, **{CAPTURE_ENV[0]: str(out_dir), CAPTURE_ENV[1]: str(worktree)})
    return subprocess.run([sys.executable, *ARGV63, "-p", "scripts.chain_checkpoint_writer"], cwd=worktree, env=env).returncode


def _layers(worktree):
    spec = importlib.util.spec_from_file_location("_ckpt_chain_identity", worktree / "scripts/chain_identity.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    rule = json.loads((worktree / "architecture/chain-compaction/identity-rule.json").read_bytes())
    return [(slot, module) for slot, module, _, _ in mod.walk_layers(lambda p: (worktree / p).read_bytes(), rule)]


def assemble(worktree, out_dir, slot, size_bound=None):
    shards = sorted(out_dir.glob("shard-*.json"))
    if len(shards) != 1:
        raise Refused("expected one capture shard (a serial run), found %d" % len(shards))
    shard = json.loads(shards[0].read_bytes())
    if shard["attested"]:
        raise Refused("a checkpoint written by an attested run (condition (i))")
    outcomes, seconds = {}, {}
    for nodeid, when, outcome, duration in shard["reports"]:
        outcomes.setdefault(nodeid, {})[when] = outcome
        seconds[nodeid] = seconds.get(nodeid, 0.0) + duration
    executed = sum(1 for o in outcomes.values() if "call" in o or o.get("setup") in ("failed", "skipped"))
    if executed != shard["collected"]:
        raise Refused("the full-run proof fails: collected %d, executed %d" % (shard["collected"], executed))
    authority = json.loads((worktree / AUTHORITY_PATH).read_bytes())
    layers = []
    for lslot, module in _layers(worktree):
        if lslot >= slot:
            continue
        validator = "scripts/%s.py" % module
        test = "tests/test_%s.py" % module.replace("validate_", "", 1)
        test = test if (worktree / test).is_file() else None
        nodes = sorted(n for n in outcomes if test and n.split("::", 1)[0] == test)
        inputs = sorted({p for n in nodes for p in shard["opened"].get(n, ())} - {validator, test, RECORD_PATH})
        for p in inputs:
            if not (worktree / p).resolve().is_relative_to(worktree.resolve()):
                raise Refused("an input outside the repository: layer %d" % lslot)
        layers.append({"slot": lslot, "module": module, "validatorPath": validator,
                       "validatorSha256": sha((worktree / validator).read_bytes()),
                       **({"testFilePath": test, "testFileSha256": sha((worktree / test).read_bytes())} if test else {}),
                       "inputs": {p: sha((worktree / p).read_bytes()) for p in inputs if (worktree / p).is_file()},
                       "nodes": [{"nodeSha256": sha(n.encode("utf-8")), **{k: outcomes[n].get(k) for k in ("setup", "call", "teardown")}}
                                 for n in nodes],
                       "seconds": round(sum(seconds[n] for n in nodes), 3)})
    pairs = []
    for layer in layers:   # V006-P2-2: a layer's pair list as data, each entry two distinct ids and a ruled type
        tree = __import__("ast").parse((worktree / layer["validatorPath"]).read_bytes())
        for node in tree.body:
            if isinstance(node, __import__("ast").Assign) and getattr(node.targets[0], "id", None) == "PAIRS_PATH":
                pairs_path = node.value.value
                for pair in json.loads((worktree / pairs_path).read_bytes())["pairs"]:
                    ids = [p["id"] for p in pair["packets"]]
                    kind = "supersession" if "superseded" in pair.get("reason", {}) else "unruled"
                    pairs.append({"layerSlot": layer["slot"], "pairsPath": pairs_path, "ids": ids, "type": kind})
    head = subprocess.run(["git", "-C", str(worktree), "rev-parse", "HEAD", "HEAD^{tree}"], capture_output=True,
                          text=True, check=True).stdout.split()
    record = {"schemaVersion": SCHEMA, "checkpointSlot": slot, "checkpointBaseline": len(authority["baselinePackets"]),
              "writingCommit": head[0], "writingTree": head[1], "parameters": PARAMETERS,
              "normalisedRecordClass": False, "layers": layers, "checkPairs": pairs,
              "fullRunProof": {"collected": shard["collected"], "executed": executed, "attested": 0},
              "writingRun": {"argv63": "direct: python " + " ".join(ARGV63) + " -p scripts.chain_checkpoint_writer",
                             "captureEnv": list(CAPTURE_ENV), "captureObservesOnly": True,
                             "otherArgv": "argv 1-62 and 64 through ci/run_packet_argv.py (the lane's dry-run kit)",
                             "verifyReference": "none: the first checkpoint records the writing run itself"}}
    raw = (json.dumps(record, sort_keys=True, indent=1) + "\n").encode()
    record["sizeBytes"], record["sizeBound"] = len(raw), size_bound
    raw = (json.dumps(record, sort_keys=True, indent=1) + "\n").encode()
    if size_bound is not None and len(raw) > size_bound:
        raise Refused("the ledger is %d bytes, over its bound %d" % (len(raw), size_bound))
    (out_dir / "record.json").write_bytes(raw)
    return len(raw), len(layers)


def rehash(worktree, record_path):
    record = json.loads(Path(record_path).read_bytes())
    bad = []
    for layer in record["layers"]:
        files = {layer["validatorPath"]: layer["validatorSha256"], **layer["inputs"]}
        if layer.get("testFilePath"):
            files[layer["testFilePath"]] = layer["testFileSha256"]
        bad += ["%d %s" % (layer["slot"], p) for p, d in files.items() if sha((worktree / p).read_bytes()) != d]
    if bad:
        raise Refused("%d attested files differ at the final commit (first: %s)" % (len(bad), bad[0]))
    return sum(len(l["inputs"]) for l in record["layers"])


if __name__ == "__main__":
    cmd, wt = sys.argv[1], Path(sys.argv[2]).resolve()
    if cmd == "run":
        sys.exit(run(wt, Path(sys.argv[3]).resolve()))
    if cmd == "assemble":
        print("ledger bytes %d, layers %d" % assemble(wt, Path(sys.argv[3]).resolve(), int(sys.argv[4]),
                                                      int(sys.argv[5]) if len(sys.argv) > 5 else None))
    elif cmd == "rehash":
        print("attested inputs re-hashed: %d" % rehash(wt, sys.argv[3]))
    else:
        raise SystemExit(__doc__)
