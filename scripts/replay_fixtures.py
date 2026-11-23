#!/usr/bin/env python3
"""HR-REPLAY-FIXTURES-001 (MET-013, slot 295): the reference model of the replay-fixture contract.

The record is architecture/replay-fixtures/record.json; the worked fixtures, their recorded trajectories, the split and
the blobs are under architecture/replay-fixtures/; the vectors are architecture/replay-fixtures/vectors.json. The contract
sits on MAS-RA-002's run manifest, which changes in no byte: every check that touches a manifest, a split declaration or
an evaluation record takes MAS-RA-002's own model (scripts/run_manifest.py) as its `rm` argument and calls it, so its
refusal codes (SHAPE, UNKNOWN_REFERENCE, TASK_SET, ...) come first. This model imports the standard library only.

Five shapes: replay-fixture/v1, replay-trajectory/v1, replay-score/v1, replay-verdict/v1 and arm-pair/v1. Record
refusals, first met first: MAS-RA-002's codes; TREE_PATH; TREE_ORDER; HELD_OUT_PUBLIC; FIXTURE_BINDING;
SELF_REPORTED_SCORE; OUTCOME_MISMATCH; BLOCKER_UNEVIDENCED; REGENERATION_MISMATCH; ARMS_IDENTICAL;
ARMS_NOT_ONE_VARIABLE; DECISION_MISMATCH (MAS-RA-002's code, met last: an arm pair's blocked count or state).
REPLAY_MATCH, REPLAY_DIVERGED and TREE_MISMATCH are replay verdicts, never refusals.
`build_fixture` is the pinned generator (fixture-builder 1): it builds a fixture from its recorded trajectory and
before-tree; a fixture's generator digest is this file's bytesDigest.
"""
from __future__ import annotations

import hashlib
import json
import re

FIXTURE_SCHEMA = "planeon.internal.replay-fixture/v1"
TRAJECTORY_SCHEMA = "planeon.internal.replay-trajectory/v1"
SCORE_SCHEMA = "planeon.internal.replay-score/v1"
VERDICT_SCHEMA = "planeon.internal.replay-verdict/v1"
ARM_PAIR_SCHEMA = "planeon.internal.arm-pair/v1"
SHAPES = (FIXTURE_SCHEMA, TRAJECTORY_SCHEMA, SCORE_SCHEMA, VERDICT_SCHEMA, ARM_PAIR_SCHEMA)
KINDS = ("FILE", "EXECUTABLE", "SYMLINK")
PARTITIONS = ("DEVELOPMENT", "HELD_OUT")
REQUEST_MATCH = ("DIGEST", "INDEX")
ACTORS = ("MODEL", "TOOL")
ENVIRONMENT_CAUSES = ("PROVIDER_UNAVAILABLE", "SANDBOX_UNAVAILABLE", "RESOURCE_UNAVAILABLE", "FIXTURE_UNAVAILABLE")
BLOCKER_CODES = ENVIRONMENT_CAUSES + ("EVALUATOR_ERROR",)
EXIT_CODES = {"COMPLETED": ("DONE",),
              "ERRORED": ("AGENT_ERROR", "TOOL_ERROR", "HARNESS_ERROR"),
              "BUDGET_EXCEEDED": ("BUDGET_TOKENS", "BUDGET_COST", "BUDGET_WALL_CLOCK", "BUDGET_ITERATIONS"),
              "BLOCKED": ENVIRONMENT_CAUSES}
OUTCOMES = ("PASSED", "FAILED", "ERRORED", "BLOCKED")
VERDICTS = ("REPLAY_MATCH", "REPLAY_DIVERGED", "TREE_MISMATCH")
RECORD_CODES = ("TREE_PATH", "TREE_ORDER", "HELD_OUT_PUBLIC", "FIXTURE_BINDING", "SELF_REPORTED_SCORE",
                "OUTCOME_MISMATCH", "BLOCKER_UNEVIDENCED", "REGENERATION_MISMATCH", "ARMS_IDENTICAL",
                "ARMS_NOT_ONE_VARIABLE", "DECISION_MISMATCH")
LOCK_NAMES = ("specsDigest", "promptDigests", "toolSchemaDigests", "imageDigests", "dependencyLockDigests",
              "fixtureDigest", "datasetDigest", "evaluator", "environmentDigest")   # MAS-RA-002's LOCK_KEYS
VARIABLES = ("model", "harness.commit", "budget", "agentCount") + tuple("locks." + k for k in LOCK_NAMES)
H16_STATES = ("PASS", "WARN", "FAIL")
GENERATOR_ID, GENERATOR_VERSION = "fixture-builder", "1"
MAX_SCORE = 1_000_000
MAX_INT = 2 ** 53 - 1
MAX_PATH_BYTES = 4096
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
FOLD = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


class Refused(ValueError):
    """A record breaks a rule; `code` is one of RECORD_CODES or a MAS-RA-002 code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def need(ok, code: str) -> None:
    if not ok:
        raise Refused(code)


def _guarded(run):
    try:
        return run()
    except (KeyError, TypeError, AttributeError, IndexError, UnicodeError, RecursionError) as exc:
        raise Refused("SHAPE") from exc


# ---------------------------------------------------------------- the two digest forms (draft section 2)

def canonical(value) -> bytes:
    """RFC 8785 bytes of an integer-only I-JSON value: keys sorted, no whitespace, UTF-8 (MAS-RA-002's form)."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def bytes_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------- shape helpers

def _closed(value, keys, optional=()) -> bool:
    return type(value) is dict and set(keys) <= set(value) <= set(keys) | set(optional)


def _text(value, limit: int = 1024) -> bool:
    return type(value) is str and 0 < len(value) <= limit


def _ident(value) -> bool:
    return type(value) is str and IDENT.match(value) is not None


def _digest(value) -> bool:
    return type(value) is str and DIGEST.match(value) is not None


def _int(value, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


# ---------------------------------------------------------------- trees and the path grammar (3.1)

def _tree_shape(tree) -> bool:
    return (_closed(tree, ("entries",)) and type(tree["entries"]) is list
            and all(_closed(e, ("path", "kind", "digest")) and type(e["path"]) is str and e["kind"] in KINDS
                    and _digest(e["digest"]) for e in tree["entries"]))


def path_ok(path) -> bool:
    """One path of the grammar: relative, no empty, "." or ".." segment, no backslash or control character, at most
    4,096 UTF-8 bytes."""
    return (type(path) is str and path != "" and not path.startswith("/") and not path.endswith("/")
            and "\\" not in path and not any(ord(c) < 0x20 for c in path)
            and len(path.encode("utf-8")) <= MAX_PATH_BYTES
            and all(seg not in ("", ".", "..") for seg in path.split("/")))


def _resolve(link: str, target: str):
    """The lexical resolution of a SYMLINK target against its link's directory; None when it leaves the tree."""
    parts = link.split("/")[:-1]
    for seg in target.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(seg)
    return "/".join(parts)


def check_tree_paths(tree, blobs) -> None:
    """TREE_PATH: the grammar, case-fold collisions (duplicates included), directory prefixes, and SYMLINK targets (read
    from the blob store by their digest; a missing target is TREE_PATH: the link cannot be shown to stay inside)."""
    paths = [e["path"] for e in tree["entries"]]
    need(all(path_ok(p) for p in paths), "TREE_PATH")
    folded = [p.translate(FOLD) for p in paths]
    need(len(set(folded)) == len(folded), "TREE_PATH")
    need(not any(q.startswith(p + "/") for p in paths for q in paths), "TREE_PATH")
    files = {e["path"] for e in tree["entries"] if e["kind"] in ("FILE", "EXECUTABLE")}
    for entry in tree["entries"]:
        if entry["kind"] == "SYMLINK":
            raw = blobs.get(entry["digest"])
            need(raw is not None and bytes_digest(raw) == entry["digest"], "TREE_PATH")
            target = raw.decode("utf-8")
            need(target != "" and not target.startswith("/") and "\x00" not in target, "TREE_PATH")
            need(_resolve(entry["path"], target) in files, "TREE_PATH")


def check_tree_order(tree) -> None:
    paths = [e["path"] for e in tree["entries"]]
    need(paths == sorted(paths, key=lambda p: p.encode("utf-8")), "TREE_ORDER")


def trees_equal(after, expected, ignored) -> bool:
    """The after-comparison: equal entries (path, kind, digest) outside the exact ignored paths."""
    pick = lambda tree: sorted((e["path"], e["kind"], e["digest"]) for e in tree["entries"] if e["path"] not in ignored)
    return pick(after) == pick(expected)


# ---------------------------------------------------------------- replay-fixture/v1 (3.1, 4.5)

FIXTURE_KEYS = ("schemaVersion", "fixtureId", "suiteDigest", "taskId", "taskDigest", "split", "workspaceBefore",
                "expectedAfter", "ignoredPaths", "trajectoryDigest", "requestMatch", "generator")


def _fixture_shape(doc) -> bool:
    return (_closed(doc, FIXTURE_KEYS, ("requestMatchReason",)) and doc["schemaVersion"] == FIXTURE_SCHEMA
            and _ident(doc["fixtureId"]) and _digest(doc["suiteDigest"]) and _ident(doc["taskId"])
            and _digest(doc["taskDigest"]) and _closed(doc["split"], ("declarationDigest", "partition"))
            and _digest(doc["split"]["declarationDigest"]) and doc["split"]["partition"] in PARTITIONS
            and _tree_shape(doc["workspaceBefore"]) and _tree_shape(doc["expectedAfter"])
            and type(doc["ignoredPaths"]) is list
            and all(_closed(x, ("path", "reason")) and type(x["path"]) is str and _text(x["reason"])
                    for x in doc["ignoredPaths"])
            and (doc["trajectoryDigest"] is None or _digest(doc["trajectoryDigest"]))
            and doc["requestMatch"] in REQUEST_MATCH
            and ("requestMatchReason" in doc) == (doc["requestMatch"] == "INDEX")
            and ("requestMatchReason" not in doc or _text(doc["requestMatchReason"]))
            and _closed(doc["generator"], ("id", "version", "digest")) and _ident(doc["generator"]["id"])
            and _text(doc["generator"]["version"], 64) and _digest(doc["generator"]["digest"]))


def check_fixture(doc, blobs, public: bool = True) -> dict:
    """A fixture: SHAPE; TREE_PATH (both trees and the ignored paths); TREE_ORDER; HELD_OUT_PUBLIC in a public store."""
    def run():
        need(_fixture_shape(doc), "SHAPE")
        for tree in (doc["workspaceBefore"], doc["expectedAfter"]):
            check_tree_paths(tree, blobs)
        ignored = [x["path"] for x in doc["ignoredPaths"]]
        need(all(path_ok(p) for p in ignored) and len({p.translate(FOLD) for p in ignored}) == len(ignored),
             "TREE_PATH")
        for tree in (doc["workspaceBefore"], doc["expectedAfter"]):
            check_tree_order(tree)
        need(not (public and doc["split"]["partition"] == "HELD_OUT"), "HELD_OUT_PUBLIC")
        return {"digest": digest(doc), "taskId": doc["taskId"], "partition": doc["split"]["partition"]}
    return _guarded(run)


# ---------------------------------------------------------------- replay-trajectory/v1 (3.2; R00's exit list)

TRAJECTORY_KEYS = ("schemaVersion", "trajectoryId", "taskId", "manifest", "steps", "exit")


def check_trajectory(doc, blobs, splits, rm) -> dict:
    """A trajectory: SHAPE (closed; steps 1..n; exit.code in its status's closed list, never EVALUATOR_ERROR); the
    embedded manifest through MAS-RA-002's check_manifest; the task in the manifest's partition (TASK_SET); every step
    blob in the store (UNKNOWN_REFERENCE) under its own bytesDigest (SHAPE)."""
    def run():
        steps = doc["steps"] if type(doc) is dict else None
        need(_closed(doc, TRAJECTORY_KEYS) and doc["schemaVersion"] == TRAJECTORY_SCHEMA and _ident(doc["trajectoryId"])
             and _ident(doc["taskId"]) and type(doc["manifest"]) is dict and type(steps) is list and steps
             and all(_closed(s, ("index", "actor", "requestDigest", "responseDigest")) and type(s["index"]) is int
                     and s["actor"] in ACTORS and _digest(s["requestDigest"]) and _digest(s["responseDigest"])
                     for s in steps)
             and [s["index"] for s in steps] == list(range(1, len(steps) + 1))
             and _closed(doc["exit"], ("status", "code")) and doc["exit"]["status"] in EXIT_CODES
             and doc["exit"]["code"] in EXIT_CODES[doc["exit"]["status"]], "SHAPE")
        facts = rm.check_manifest(doc["manifest"], splits)
        split = splits[doc["manifest"]["split"]["declarationDigest"]]
        tasks = [t["taskId"] for t in split["partitions"][doc["manifest"]["split"]["partition"]]]
        need(doc["taskId"] in tasks, "TASK_SET")
        for step in steps:
            for d in (step["requestDigest"], step["responseDigest"]):
                need(d in blobs, "UNKNOWN_REFERENCE")
                need(bytes_digest(blobs[d]) == d, "SHAPE")
        return {"digest": digest(doc), "manifestDigest": facts["digest"], "taskId": doc["taskId"],
                "exit": doc["exit"]["status"]}
    return _guarded(run)


# ---------------------------------------------------------------- the pinned generator (4.4)

def apply_writes(before, trajectory, blobs) -> dict:
    """The after-tree a recorded trajectory leaves: its TOOL steps' write_file calls ({"tool": "write_file", "path",
    "content", "mode"?}) applied to the before-tree, mode EXECUTABLE or FILE."""
    entries = {e["path"]: e for e in before["entries"]}
    for step in trajectory["steps"]:
        if step["actor"] == "TOOL":
            call = json.loads(blobs[step["requestDigest"]].decode("utf-8"))
            need(call.get("tool") == "write_file", "REGENERATION_MISMATCH")
            entries[call["path"]] = {"path": call["path"], "kind": call.get("mode", "FILE"),
                                     "digest": bytes_digest(call["content"].encode("utf-8"))}
    return {"entries": [entries[p] for p in sorted(entries, key=lambda p: p.encode("utf-8"))]}


def build_fixture(fixture_id, task, before, trajectory, blobs, generator_digest, request_match="DIGEST", reason=None):
    """fixture-builder 1: a fixture from its task ({suiteDigest, taskId, taskDigest, split}), its before-tree and its
    recorded trajectory."""
    doc = {"schemaVersion": FIXTURE_SCHEMA, "fixtureId": fixture_id, "suiteDigest": task["suiteDigest"],
           "taskId": task["taskId"], "taskDigest": task["taskDigest"], "split": dict(task["split"]),
           "workspaceBefore": before, "expectedAfter": apply_writes(before, trajectory, blobs), "ignoredPaths": [],
           "trajectoryDigest": digest(trajectory), "requestMatch": request_match,
           "generator": {"id": GENERATOR_ID, "version": GENERATOR_VERSION, "digest": generator_digest}}
    if request_match == "INDEX":
        doc["requestMatchReason"] = reason
    return doc


def check_regeneration(stored, rebuilt, blobs) -> dict:
    """4.4: a rebuild by the pinned generator from the pinned trajectory and before-tree keeps the id only when it is
    byte-equal in canonical form; any other rebuild is a new fixture id (it inherits nothing)."""
    def run():
        check_fixture(stored, blobs)
        check_fixture(rebuilt, blobs)
        need(rebuilt["generator"] == stored["generator"] and rebuilt["trajectoryDigest"] == stored["trajectoryDigest"]
             and rebuilt["workspaceBefore"] == stored["workspaceBefore"], "REGENERATION_MISMATCH")
        if rebuilt["fixtureId"] == stored["fixtureId"]:
            need(canonical(rebuilt) == canonical(stored), "REGENERATION_MISMATCH")
            return {"keptId": True}
        return {"keptId": False, "newId": rebuilt["fixtureId"]}
    return _guarded(run)


# ---------------------------------------------------------------- replay-score/v1 (3.3, 3.4, 3.5, 4.3)

SCORE_KEYS = ("schemaVersion", "scoreId", "manifestDigest", "results", "scoredFrom")
RESULT_KEYS = ("taskId", "fixtureDigest", "trajectoryDigest", "exitStatus", "outcome", "score", "blockerCode",
               "evidenceDigest")


def _outcome(r, fixture, trajectory, after) -> None:
    """Draft 3.3's map plus F2's row (COMPLETED with the GRADE record in envelope ERROR: BLOCKED, 0, EVALUATOR_ERROR)."""
    status, outcome, score, code = r["exitStatus"], r["outcome"], r["score"], r["blockerCode"]
    need(status == trajectory["exit"]["status"], "OUTCOME_MISMATCH")
    if outcome != "BLOCKED":
        need(code is None and r["evidenceDigest"] is None, "OUTCOME_MISMATCH")
    if status == "COMPLETED" and outcome == "BLOCKED":
        need(code == "EVALUATOR_ERROR" and score == 0, "OUTCOME_MISMATCH")
    elif status == "COMPLETED":
        ignored = {x["path"] for x in fixture["ignoredPaths"]}
        if trees_equal(after, fixture["expectedAfter"], ignored):
            need(outcome == "PASSED" and score == MAX_SCORE, "OUTCOME_MISMATCH")
        else:
            need(outcome == "FAILED" and 0 <= score < MAX_SCORE, "OUTCOME_MISMATCH")
    elif status in ("ERRORED", "BUDGET_EXCEEDED"):
        need(outcome == "ERRORED" and score == 0, "OUTCOME_MISMATCH")
    else:
        need(outcome == "BLOCKED" and score == 0 and code != "EVALUATOR_ERROR", "OUTCOME_MISMATCH")


def _evidence(r, ctx) -> None:
    if r["outcome"] != "BLOCKED":
        return
    need(r["blockerCode"] is not None and r["evidenceDigest"] is not None, "BLOCKER_UNEVIDENCED")
    if r["blockerCode"] == "EVALUATOR_ERROR":
        need(ctx.get("gradeRecords", {}).get(r["evidenceDigest"], {}).get("envelope") == "ERROR", "BLOCKER_UNEVIDENCED")
    else:
        need(r["evidenceDigest"] in ctx.get("environmentEvidence", []), "BLOCKER_UNEVIDENCED")


def check_score(doc, ctx, rm) -> dict:
    """One scoring record per run. ctx: manifests, splits, fixtures, trajectories (each by digest), blobs, fixtureSet
    (F), afterTrees (by task id), environmentEvidence, gradeRecords. Returns whether the run may enter a MAS-RA-002
    evaluation record (3.5: never with a BLOCKED result)."""
    def run():
        results = doc["results"] if type(doc) is dict else None
        need(_closed(doc, SCORE_KEYS) and doc["schemaVersion"] == SCORE_SCHEMA and _ident(doc["scoreId"])
             and _digest(doc["manifestDigest"]) and _text(doc["scoredFrom"], 64) and type(results) is list and results
             and all(_closed(r, RESULT_KEYS) and _ident(r["taskId"]) and _digest(r["fixtureDigest"])
                     and _digest(r["trajectoryDigest"]) and r["exitStatus"] in EXIT_CODES and r["outcome"] in OUTCOMES
                     and _int(r["score"], 0, MAX_SCORE) and (r["blockerCode"] is None or r["blockerCode"] in BLOCKER_CODES)
                     and (r["evidenceDigest"] is None or _digest(r["evidenceDigest"])) for r in results), "SHAPE")
        need(len({r["taskId"] for r in results}) == len(results), "DUPLICATE_ID")
        manifest = ctx["manifests"].get(doc["manifestDigest"])
        need(manifest is not None, "UNKNOWN_REFERENCE")
        facts = rm.check_manifest(manifest, ctx["splits"])
        need(facts["digest"] == doc["manifestDigest"], "UNKNOWN_REFERENCE")
        split = ctx["splits"][manifest["split"]["declarationDigest"]]
        tasks = sorted(t["taskId"] for t in split["partitions"][manifest["split"]["partition"]])
        need(sorted(r["taskId"] for r in results) == tasks, "TASK_SET")
        for r in results:
            fixture, trajectory = ctx["fixtures"].get(r["fixtureDigest"]), ctx["trajectories"].get(r["trajectoryDigest"])
            need(fixture is not None and trajectory is not None and digest(fixture) == r["fixtureDigest"]
                 and digest(trajectory) == r["trajectoryDigest"], "UNKNOWN_REFERENCE")
            need(r["exitStatus"] != "COMPLETED" or r["taskId"] in ctx.get("afterTrees", {}), "UNKNOWN_REFERENCE")
            check_trajectory(trajectory, ctx["blobs"], ctx["splits"], rm)
            need(digest(trajectory["manifest"]) == doc["manifestDigest"], "CONFIGURATION_MIXED")
        for r in results:
            check_fixture(ctx["fixtures"][r["fixtureDigest"]], ctx["blobs"])
        fset = ctx["fixtureSet"]
        need(type(fset) is list and fset == sorted(set(fset)) and digest(fset) == manifest["locks"]["fixtureDigest"],
             "FIXTURE_BINDING")
        need(all(d in ctx["fixtures"] for d in fset)
             and sorted(ctx["fixtures"][d]["taskId"] for d in fset) == tasks, "FIXTURE_BINDING")
        need(all(r["fixtureDigest"] in fset and ctx["fixtures"][r["fixtureDigest"]]["taskId"] == r["taskId"]
                 and ctx["trajectories"][r["trajectoryDigest"]]["taskId"] == r["taskId"] for r in results),
             "FIXTURE_BINDING")
        need(doc["scoredFrom"] == "TRACE", "SELF_REPORTED_SCORE")
        for r in results:
            _outcome(r, ctx["fixtures"][r["fixtureDigest"]], ctx["trajectories"][r["trajectoryDigest"]],
                     ctx.get("afterTrees", {}).get(r["taskId"]))
        for r in results:
            _evidence(r, ctx)
        return {"digest": digest(doc), "enters": all(r["outcome"] != "BLOCKED" for r in results),
                "scores": {r["taskId"]: r["score"] for r in results}}
    return _guarded(run)


# ---------------------------------------------------------------- the keyless replay (U1, 3.2) and replay-verdict/v1

def replay(fixture, trajectory, blobs, sent, after) -> dict:
    """U1 against a recorded list of sent MODEL requests and the after-tree (no harness runs here). The fixture's trees
    pass the path grammar before anything is materialised. DIGEST: the first MODEL step whose sent request differs is
    REPLAY_DIVERGED and the replay stops; INDEX: answered by index alone. TOOL steps are never compared."""
    def run():
        check_fixture(fixture, blobs)
        need(fixture["trajectoryDigest"] is not None and digest(trajectory) == fixture["trajectoryDigest"],
             "UNKNOWN_REFERENCE")
        model_steps = [s for s in trajectory["steps"] if s["actor"] == "MODEL"]
        if fixture["requestMatch"] == "DIGEST":
            for i, step in enumerate(model_steps):
                if i >= len(sent) or bytes_digest(sent[i]) != step["requestDigest"]:
                    return {"verdict": "REPLAY_DIVERGED", "divergedAtStep": step["index"], "afterTreeDigest": None,
                            "requestMatch": "DIGEST"}
        ignored = {x["path"] for x in fixture["ignoredPaths"]}
        verdict = "REPLAY_MATCH" if trees_equal(after, fixture["expectedAfter"], ignored) else "TREE_MISMATCH"
        return {"verdict": verdict, "divergedAtStep": None, "afterTreeDigest": digest(after),
                "requestMatch": fixture["requestMatch"]}
    return _guarded(run)


VERDICT_KEYS = ("schemaVersion", "verdictId", "fixtureDigest", "harnessCommit", "environmentDigest", "requestMatch",
                "verdict", "divergedAtStep", "afterTreeDigest")


def check_verdict(doc) -> dict:
    """replay-verdict/v1 (3.6): divergedAtStep only for REPLAY_DIVERGED, and afterTreeDigest null exactly then."""
    def run():
        diverged = doc["verdict"] == "REPLAY_DIVERGED"
        need(_closed(doc, VERDICT_KEYS) and doc["schemaVersion"] == VERDICT_SCHEMA and _ident(doc["verdictId"])
             and _digest(doc["fixtureDigest"]) and type(doc["harnessCommit"]) is str
             and COMMIT.match(doc["harnessCommit"]) is not None and _digest(doc["environmentDigest"])
             and doc["requestMatch"] in REQUEST_MATCH and doc["verdict"] in VERDICTS
             and (_int(doc["divergedAtStep"], 1, MAX_INT) if diverged else doc["divergedAtStep"] is None)
             and (doc["afterTreeDigest"] is None if diverged else _digest(doc["afterTreeDigest"])), "SHAPE")
        return {"verdict": doc["verdict"]}
    return _guarded(run)


# ---------------------------------------------------------------- arm-pair/v1 (4.2, 4.3)

def arm_fields(arm) -> dict:
    """The configuration tuple and the locks of one arm, by field name."""
    c = arm["configuration"]
    fields = {"model": c["model"], "harness.commit": c["harness"]["commit"], "harness.dirty": c["harness"]["dirty"],
              "budget": c["budget"], "agentCount": c["agentCount"]}
    fields.update({"locks." + k: arm["locks"][k] for k in LOCK_NAMES})
    return fields


def check_arm_pair(doc, ctx) -> dict:
    """C-ONE-VAR and C-BLOCKED. ctx: baseline and candidate ({configuration, locks}), gateState (the distribution gate's
    H16 state) and blocked (the BLOCKED task count over both arms). ARMS_IDENTICAL when nothing differs,
    ARMS_NOT_ONE_VARIABLE when anything but the named variable differs; then the pair's blocked count and state (UNRESOLVED
    when any task is blocked, else the gate's): R00's c1 call, MAS-RA-002's DECISION_MISMATCH."""
    def run():
        need(_closed(doc, ("schemaVersion", "pairId", "comparisonDigest", "variable", "blockedTasks", "state"))
             and doc["schemaVersion"] == ARM_PAIR_SCHEMA and _ident(doc["pairId"]) and _digest(doc["comparisonDigest"])
             and doc["variable"] in VARIABLES and _int(doc["blockedTasks"], 0, MAX_INT)
             and doc["state"] in H16_STATES + ("UNRESOLVED",), "SHAPE")
        base, cand = arm_fields(ctx["baseline"]), arm_fields(ctx["candidate"])
        differ = {k for k in base if base[k] != cand[k]}
        need(differ, "ARMS_IDENTICAL")
        need(differ == {doc["variable"]}, "ARMS_NOT_ONE_VARIABLE")
        need(doc["blockedTasks"] == ctx["blocked"], "DECISION_MISMATCH")
        need(doc["state"] == ("UNRESOLVED" if ctx["blocked"] > 0 else ctx["gateState"]), "DECISION_MISMATCH")
        return {"differs": sorted(differ), "state": doc["state"]}
    return _guarded(run)


# ---------------------------------------------------------------- MAS-RA-002's evaluation record (4.1, U2)

def evaluation_mean(record, manifests, splits, rm) -> dict:
    """A MAS-RA-002 evaluation record through its own model, and the mean score per task run in parts per million."""
    facts = rm.check_record(record, manifests, splits)
    cells = len(facts["tasks"]) * facts["runs"]
    return {"complete": facts["complete"], "meanPpm": sum(facts["sums"].values()) // cells if cells else 0}


# ---------------------------------------------------------------- vectors

def _blobs(stores, data) -> dict:
    raw = dict(stores.get("blobs", {}))
    raw.update(data.get("blobs", {}))
    return {k: v.encode("utf-8") for k, v in raw.items()}


def _store(stores, data, name) -> dict:
    merged = dict(stores.get(name, {}))
    merged.update(data.get(name, {}))
    return merged


def _held_out_in_memory(doc, data):
    """The HELD_OUT_PUBLIC vector's document is built here in memory from a stored DEVELOPMENT fixture (4.5): no
    HELD_OUT fixture is stored anywhere in a public file."""
    if data.get("inMemoryPartition"):
        doc = json.loads(json.dumps(doc))
        doc["split"]["partition"] = data["inMemoryPartition"]
    return doc


def evaluate(check: str, data: dict, stores: dict, rm):
    """(None, result) when accepted, (code, {}) when refused; `rm` is MAS-RA-002's model (scripts/run_manifest.py)."""
    blobs = _blobs(stores, data)
    splits, manifests = _store(stores, data, "splits"), _store(stores, data, "manifests")
    fixtures, trajectories = _store(stores, data, "fixtures"), _store(stores, data, "trajectories")
    pick = lambda key, store: data[key] if type(data[key]) is dict else store[data[key]]
    try:
        if check == "FIXTURE":
            result = check_fixture(_held_out_in_memory(pick("fixture", fixtures), data), blobs)
        elif check == "TRAJECTORY":
            result = check_trajectory(pick("trajectory", trajectories), blobs, splits, rm)
        elif check == "SCORE":
            ctx = {"manifests": manifests, "splits": splits, "fixtures": fixtures, "trajectories": trajectories,
                   "blobs": blobs, "fixtureSet": data["fixtureSet"], "afterTrees": data.get("afterTrees", {}),
                   "environmentEvidence": data.get("environmentEvidence", []),
                   "gradeRecords": data.get("gradeRecords", {})}
            result = check_score(data["score"], ctx, rm)
        elif check == "REGENERATION":
            result = check_regeneration(pick("stored", fixtures), data["rebuilt"], blobs)
        elif check == "REPLAY":
            sent = [s.encode("utf-8") for s in data["sent"]]
            result = replay(pick("fixture", fixtures), pick("trajectory", trajectories), blobs, sent, data["after"])
        elif check == "VERDICT":
            result = check_verdict(data["verdict"])
        elif check == "ARM_PAIR":
            result = check_arm_pair(data["pair"], data)
        elif check == "EVALUATION":
            result = evaluation_mean(data["record"], manifests, splits, rm)
        else:
            raise KeyError(check)
    except Exception as exc:  # a refusal of this model or of MAS-RA-002's carries its code
        if getattr(exc, "code", None) is None:
            raise
        return exc.code, {}
    return None, result


def replay_case(case: dict, stores: dict, rm):
    """(ok, got): whether the case's expectation holds, and what the model gave."""
    code, result = evaluate(case["check"], case["input"], stores, rm)
    expect = case["expect"]
    if "refuse" in expect:
        return code == expect["refuse"], code
    ok = code is None and all(result.get(k) == v for k, v in expect.get("result", {}).items())
    return ok, code if code else result
