"""MET-PERF-047 (CHAIN-COMPACTION-002): the checkpoint writer and its capture plugin. Lane-run only; never in the 64 argv.

usage: chain_checkpoint_writer.py run WORKTREE OUT_DIR
       chain_checkpoint_writer.py assemble WORKTREE OUT_DIR SLOT --argv-run FILE (--measure-only | --size-bound N) [--dry-run-only]
       chain_checkpoint_writer.py rehash WORKTREE RECORD

The writing run's two stated differences (Q-282C-3, MON-282-Q1Q3), always given together: (1) argv 63 runs directly,
not through ci/run_packet_argv.py, with `-p scripts.chain_checkpoint_writer` and the capture variables; (2) it runs
SERIAL: the -p option keeps ci/parallel_suite.py's serial loop, so one process runs every node, where the verify runs 8
workers. An outcome that differs between this run and the 8-worker shadow verify 0 is attributed to these two first.
Argv 1-62 and 64 run through the runner (the lane's dry-run kit); their run summary is bound by sha256 (--argv-run).

The capture observes only: one audit hook on "open" notes, per node and phase, the repository files opened for reading
(write flags excluded, os.open judged by its flags); collection-time opens are charged to every node of the module;
opens outside the repository are counted, never inputs; the node is cleared after each teardown. It writes only its
shard under OUT_DIR, which must lie outside the worktree. The writer refuses: OUT_DIR inside the worktree; a reader
whose MODE is not "shadow" (condition (i): no checkpoint from an attested run); deselected nodes; a failed full-run proof
(executed != collected); an argv run summary with a non-zero rc; a ledger over its bound (it never truncates). At W it
measures the size (--measure-only); at F the bound is required. Remaining capture gaps: opens by subprocesses and
files read through memory maps already open are not seen, and
process-level caches (a module imported, or a file read into an lru cache, by an earlier node) are charged to the first
node that read them only.

The exclusion (MON-282-W2-RULED): the step's own products are never a layer's input: its authority, its hunk-class
record and record.json (exclusion.files), and the head validator's AUTHORITY_SHA256 pin line (exclusion.pinLine:
that file is attested with the line normalised by the reader's own pin_normalised, since the pin is filled after the
ledger is written). The exclusion equals the bounded build's write set (F checks the two equal)."""
import ast
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

CAPTURE_ENV = ("CHAIN_CHECKPOINT_CAPTURE_DIR", "CHAIN_CHECKPOINT_CAPTURE_ROOT")
RECORD_PATH = "architecture/chain-checkpoint/record.json"
AUTHORITY_PATH = "architecture/chain-checkpoint-authority.json"
HUNK_CLASSES_DIR = "architecture/chain-checkpoint/hunk-classes"
SCHEMA = "harness.planeon.ai/chain-checkpoint/v1"
ARGV63 = ["-m", "pytest", "tests", "ci/test_offline_runner.py", "ci/test_warm_snapshot.py"]
INDEX_RECORDS = ("architecture/review-record/briefs.json", "task-packets/README.md",
                 "docs/repositories/00-harness-engineering.md", "docs/MASTER_DEVELOPMENT_PLAN.md")
SKIP_PARTS = (".git", "__pycache__", ".venv", ".pytest_cache")
WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
STATED = ["direct: argv 63 runs outside ci/run_packet_argv.py, with -p scripts.chain_checkpoint_writer and the capture variables",
          "serial: the -p option keeps ci/parallel_suite.py's serial loop (one process); the verify runs 8 workers"]


class Refused(SystemExit):
    def __init__(self, message):
        super().__init__("chain checkpoint writer refused: %s" % message)


# ---- the capture plugin (loaded by -p in the writing run only) ----
_state = {"node": None, "opened": {}, "reports": [], "collected": 0, "deselected": 0, "outside": 0}


def _audit(event, args):
    if event != "open" or _state["node"] is None or not args:
        return
    path, mode = args[0], args[1] if len(args) > 1 else None
    flags = args[2] if len(args) > 2 else 0
    if not isinstance(path, (str, bytes)) or (isinstance(mode, str) and any(m in mode for m in "wax+")) \
            or (mode is None and isinstance(flags, int) and flags & WRITE_FLAGS):
        return
    try:
        rel = os.path.relpath(os.path.realpath(os.fsdecode(path)), os.path.realpath(os.environ.get(CAPTURE_ENV[1])))
    except (TypeError, ValueError):
        return
    if rel.startswith(".."):
        _state["outside"] += 1
        return
    if any(part in SKIP_PARTS for part in Path(rel).parts):
        return
    _state["opened"].setdefault(_state["node"], set()).add(Path(rel).as_posix())


def pytest_configure(config):
    if os.environ.get(CAPTURE_ENV[0]):
        sys.addaudithook(_audit)


def pytest_make_collect_report(collector):
    _state["node"] = "collect:" + collector.nodeid.split("::", 1)[0]


def pytest_collection_finish(session):
    _state["collected"], _state["node"] = len(session.items), None


def pytest_deselected(items):
    _state["deselected"] += len(items)


def pytest_runtest_setup(item):
    _state["node"] = item.nodeid


def pytest_runtest_call(item):
    _state["node"] = item.nodeid


def pytest_runtest_teardown(item):
    _state["node"] = item.nodeid


def pytest_runtest_logreport(report):
    _state["reports"].append([report.nodeid, report.when, report.outcome, round(report.duration, 4)])
    if report.when == "teardown":
        _state["node"] = None


def pytest_sessionfinish(session, exitstatus):
    out = os.environ.get(CAPTURE_ENV[0])
    if out:
        (Path(out) / ("shard-%d.json" % os.getpid())).write_text(json.dumps(
            {"collected": _state["collected"], "deselected": _state["deselected"], "outside": _state["outside"],
             "reports": _state["reports"], "opened": {k: sorted(v) for k, v in _state["opened"].items()}}, sort_keys=True),
            encoding="utf-8")


# ---- the writer ----
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def _outside(worktree, out_dir):
    if out_dir.resolve().is_relative_to(worktree.resolve()):
        raise Refused("OUT_DIR lies inside the worktree")


def run(worktree, out_dir):
    _outside(worktree, out_dir)
    out_dir.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, **{CAPTURE_ENV[0]: str(out_dir), CAPTURE_ENV[1]: str(worktree)})
    return subprocess.run([sys.executable, *ARGV63, "-p", "scripts.chain_checkpoint_writer"], cwd=worktree, env=env).returncode


def _constant(path, name):
    for node in ast.parse(path.read_bytes()).body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", None) == name:
            return ast.literal_eval(node.value)
    return None


def check_pairs_of(lslot, pairs_path, document):
    """A layer's check pairs from its pairs file, each (layerSlot, the sorted ids, type) once (MON-282-PAIRS-DEDUPE): a
    pairs file may hold one entry per overlapping path for the same packet pair, and the reader's check_pairs refuses a
    repeated entry (V006-P2-2)."""
    out, seen = [], set()
    for pair in document["pairs"]:
        entry = {"layerSlot": lslot, "pairsPath": pairs_path, "ids": [p["id"] for p in pair["packets"]],
                 "type": "supersession" if "superseded" in pair.get("reason", {}) else "unruled"}
        key = (lslot, tuple(sorted(entry["ids"])), entry["type"])
        if key not in seen:
            seen.add(key)
            out.append(entry)
    return out


def exclusion_for(slot, head_validator):
    """MON-282-W2-RULED: the closed exclusion of the step at slot: its own products, never a layer's input."""
    return {"files": sorted([AUTHORITY_PATH, "%s/%d.json" % (HUNK_CLASSES_DIR, slot), RECORD_PATH]), "pinLine": head_validator}


def _pin_normaliser(worktree):
    """The reader's own pin_normalised (one rule for the writer and the reader), loaded by path."""
    spec = importlib.util.spec_from_file_location("_ckpt_reader_pin", worktree / "ci/chain_checkpoint.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.pin_normalised


def attested_sha(raw, path, pin_line, normalise):
    """A file's attested digest: its bytes', or, for the pin-line file, its bytes with the one AUTHORITY_SHA256 line
    normalised (the reader's pin_normalised); a pin-line file without exactly one such line is refused."""
    if path == pin_line:
        raw = normalise(raw)
        if raw is None:
            raise Refused("%s has no single AUTHORITY_SHA256 pin line" % path)
    return sha(raw)


def _layers(worktree):
    spec = importlib.util.spec_from_file_location("_ckpt_chain_identity", worktree / "scripts/chain_identity.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    rule = json.loads((worktree / "architecture/chain-compaction/identity-rule.json").read_bytes())
    return [(slot, module) for slot, module, _, _ in mod.walk_layers(lambda p: (worktree / p).read_bytes(), rule)]


def assemble(worktree, out_dir, slot, argv_run, size_bound=None, measure_only=False, dry_run_only=False):
    _outside(worktree, out_dir)
    if _constant(worktree / "ci/chain_checkpoint.py", "MODE") != "shadow":
        raise Refused("the reader is not in shadow mode: no checkpoint from an attested run (condition (i))")
    if not measure_only and size_bound is None:
        raise Refused("the size bound is required at F")
    shards = sorted(out_dir.glob("shard-*.json"))
    if len(shards) != 1:
        raise Refused("expected one capture shard (the serial run), found %d" % len(shards))
    shard = json.loads(shards[0].read_bytes())
    if shard["deselected"]:
        raise Refused("%d nodes deselected" % shard["deselected"])
    summary = Path(argv_run).read_text(encoding="utf-8")
    rcs = re.findall(r"^(\d\d) rc=(\d+)", summary, re.M)
    if sorted(int(n) for n, _ in rcs) != [*range(1, 63), 64] or any(rc != "0" for _, rc in rcs):
        raise Refused("the argv run summary is not argv 1-62 and 64, each at rc=0")
    outcomes, seconds = {}, {}
    for nodeid, when, outcome, duration in shard["reports"]:
        outcomes.setdefault(nodeid, {})[when] = outcome
        seconds[nodeid] = seconds.get(nodeid, 0.0) + duration
    executed = sum(1 for o in outcomes.values() if "call" in o or o.get("setup") in ("failed", "skipped"))
    if executed != shard["collected"]:
        raise Refused("the full-run proof fails: collected %d, executed %d" % (shard["collected"], executed))
    authority = json.loads((worktree / AUTHORITY_PATH).read_bytes())
    chain = _layers(worktree)
    heads = ["scripts/%s.py" % module for lslot, module in chain if lslot == slot]
    if len(heads) != 1:
        raise Refused("no single head layer at slot %d" % slot)
    excl, normalise = exclusion_for(slot, heads[0]), _pin_normaliser(worktree)
    layers, pairs = [], []
    for lslot, module in chain:
        if lslot >= slot:
            continue
        validator = "scripts/%s.py" % module
        test = "tests/test_%s.py" % module.replace("validate_", "", 1)
        test = test if (worktree / test).is_file() else None
        apath = _constant(worktree / validator, "AUTHORITY_PATH")
        if not apath or not (worktree / apath).is_file():
            raise Refused("layer %d names no authority file" % lslot)
        nodes = sorted(n for n in outcomes if test and n.split("::", 1)[0] == test)
        opened = {p for n in nodes for p in shard["opened"].get(n, ())} | set(shard["opened"].get("collect:" + (test or ""), ()))
        inputs = sorted(opened - {validator, test, apath} - set(excl["files"]))
        layers.append({"slot": lslot, "module": module, "validatorPath": validator,
                       "validatorSha256": sha((worktree / validator).read_bytes()), "authorityPath": apath,
                       "authoritySha256": sha((worktree / apath).read_bytes()),
                       **({"testFilePath": test, "testFileSha256": sha((worktree / test).read_bytes())} if test else {}),
                       "inputs": {p: attested_sha((worktree / p).read_bytes(), p, excl["pinLine"], normalise)
                                  for p in inputs if (worktree / p).is_file()},
                       "nodes": [{"nodeSha256": sha(n.encode("utf-8")), **{k: outcomes[n].get(k) for k in ("setup", "call", "teardown")}}
                                 for n in nodes],
                       "seconds": round(sum(seconds[n] for n in nodes), 3)})
        pairs_path = _constant(worktree / validator, "PAIRS_PATH")
        if pairs_path:
            pairs += check_pairs_of(lslot, pairs_path, json.loads((worktree / pairs_path).read_bytes()))
    head = subprocess.run(["git", "-C", str(worktree), "rev-parse", "HEAD", "HEAD^{tree}"], capture_output=True, text=True,
                          check=True).stdout.split()
    captured = {p for l in layers for p in l["inputs"]}
    record = {"schemaVersion": SCHEMA, "checkpointSlot": slot, "checkpointBaseline": len(authority["baselinePackets"]),
              "writingCommit": head[0], "writingTree": head[1],
              "parameters": {"cadenceSlots": 10, "sampleFraction": 0.1, "fullRunOn": "owner-named slot", "nShadow": 10,
                             "shadowCapSeconds": 15, "workers": 8, "shadowIn": "dryRunOnly" if dry_run_only else "verify"},
              "normalisedRecordClass": bool(captured & set(INDEX_RECORDS)), "layers": layers, "checkPairs": pairs,
              "fullRunProof": {"collected": shard["collected"], "executed": executed, "deselected": 0, "attested": 0},
              "writingRun": {"statedDifferences": STATED, "captureEnv": list(CAPTURE_ENV), "captureObservesOnly": True,
                             "outsideReads": shard["outside"], "argvRunSummarySha256": sha(summary.encode()),
                             "verifyReference": "none: the first checkpoint records the writing run itself"},
              "exclusion": excl, "sizeBound": size_bound, "sizeBytes": 0}
    for _ in range(5):          # sizeBytes is the final file's length
        raw = (json.dumps(record, sort_keys=True, indent=1) + "\n").encode()
        if record["sizeBytes"] == len(raw):
            break
        record["sizeBytes"] = len(raw)
    if size_bound is not None and len(raw) > size_bound:
        raise Refused("the ledger is %d bytes, over its bound %d" % (len(raw), size_bound))
    (out_dir / "record.json").write_bytes(raw)
    return len(raw), len(layers), sorted(captured & set(INDEX_RECORDS))


def rehash(worktree, record_path):
    record = json.loads(Path(record_path).read_bytes())
    pin_line, normalise, bad = record.get("exclusion", {}).get("pinLine"), _pin_normaliser(worktree), []
    for layer in record["layers"]:
        files = {layer["validatorPath"]: layer["validatorSha256"], layer["authorityPath"]: layer["authoritySha256"], **layer["inputs"]}
        if layer.get("testFilePath"):
            files[layer["testFilePath"]] = layer["testFileSha256"]
        bad += ["%d %s" % (layer["slot"], p) for p, d in files.items()
                if attested_sha((worktree / p).read_bytes(), p, pin_line, normalise) != d]
    if bad:
        raise Refused("%d attested files differ at the final commit (first: %s)" % (len(bad), bad[0]))
    return sum(len(l["inputs"]) for l in record["layers"])


if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ["run"]:
        sys.exit(run(Path(args[1]).resolve(), Path(args[2]).resolve()))
    if args[:1] == ["assemble"]:
        flags = {a: args[i + 1] if i + 1 < len(args) else None for i, a in enumerate(args) if a.startswith("--")}
        print(assemble(Path(args[1]).resolve(), Path(args[2]).resolve(), int(args[3]), flags["--argv-run"],
                       int(flags["--size-bound"]) if "--size-bound" in flags else None, "--measure-only" in flags,
                       "--dry-run-only" in flags))
    elif args[:1] == ["rehash"]:
        print("attested inputs re-hashed: %d" % rehash(Path(args[1]).resolve(), args[2]))
    else:
        raise SystemExit(__doc__)
