#!/usr/bin/env python3
"""Run manifest and configuration-level evaluation records v1 (architecture/run-manifest/, MAS-RA-002): reference model,
DATA_CHECK_ONLY.

Five closed, content-addressed record kinds, each checked by one function that raises `Refused(code)` on the first rule it
breaks and otherwise returns derived facts:
- a split declaration (development and held-out task sets, digested before any run uses them);
- a run manifest (written before its run: the H16 scope digest, the configuration tuple (model, harness, budget,
  agentCount), the harness commit and dirty flag, every lock digest, the seed, the split and partition, the repetition);
- a configuration-level evaluation record (one configuration, one suite, one partition: k declared repetitions, the
  per-task integer scores of every run, with tokens and cost beside them);
- a distribution-gate comparison (a candidate record against a baseline record: a paired, task-clustered 95% interval of the
  difference over k >= 3 repetitions per task against a versioned tolerance, decided in integer arithmetic);
- a selection record (a choice among candidate configurations, refused when any input is held-out data).

Owner decisions (2026-10-13, via the lane monitor): Q-MAS2-A (a) an internal candidate, H16 unchanged; Q-MAS2-B (a) the
paired task-clustered interval with IMPROVED / WITHIN_NOISE / REGRESSED / UNRESOLVED in integer arithmetic; Q-MAS2-C (a)
splits digested before the first run and held-out scores refused as selection input; Q-MAS2-D (a) budget caps in the
configuration tuple, tokens and cost beside the score, never gated here. Standard library only.
"""
from __future__ import annotations

import hashlib
import json
import math
import re

SPLIT_SCHEMA = "planeon.internal.split-declaration/v1"
MANIFEST_SCHEMA = "planeon.internal.run-manifest/v1"
RECORD_SCHEMA = "planeon.internal.evaluation-record/v1"
COMPARISON_SCHEMA = "planeon.internal.distribution-gate/v1"
SELECTION_SCHEMA = "planeon.internal.selection-record/v1"
PARTITIONS = ("DEVELOPMENT", "HELD_OUT")
PURPOSES = ("NON_REGRESSION", "IMPROVEMENT")
DECISIONS = ("IMPROVED", "WITHIN_NOISE", "REGRESSED", "UNRESOLVED")
UNRESOLVED_REASONS = ("INCOMPLETE", "DIRTY_TREE", "TOO_FEW_TASKS")
SEED_MODES = ("FIXED", "PROVIDER_UNSEEDABLE")
MIN_REPETITIONS = 3
MAX_SCORE = 1_000_000
MAX_ITEMS = 4096
MAX_INT = 2 ** 53 - 1   # I-JSON: every recorded integer is exact as a double
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
TIME = re.compile(r"[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z\Z")
# Two-sided 95% critical values of Student's t in thousandths, rounded up, by degrees of freedom. t's quantile falls as df
# grows, so using the next lower tabulated df (a larger value) for an untabulated df, and the df-120 value for every df
# above 120, is conservative everywhere.
T_CRITICAL = ((1, 12707), (2, 4303), (3, 3183), (4, 2777), (5, 2571), (6, 2447), (7, 2365), (8, 2307), (9, 2263),
              (10, 2229), (11, 2201), (12, 2179), (13, 2161), (14, 2145), (15, 2132), (16, 2120), (17, 2110), (18, 2101),
              (19, 2094), (20, 2086), (21, 2080), (22, 2074), (23, 2069), (24, 2064), (25, 2060), (26, 2056), (27, 2052),
              (28, 2049), (29, 2046), (30, 2043), (40, 2022), (60, 2001), (120, 1980))
COMPARABLE_LOCKS = ("evaluator", "datasetDigest", "fixtureDigest", "environmentDigest")
STATISTICS_KEYS = ("tasks", "baselineRuns", "candidateRuns", "criticalThousandths", "meanDifferencePpm", "halfWidthPpm",
                   "nonInferior")
CODES = ("SHAPE", "DUPLICATE_ID", "UNKNOWN_REFERENCE", "PARTITION_EMPTY", "PARTITION_OVERLAP", "SPLIT_SUITE",
         "SPLIT_AFTER_RUN", "STARTED_BEFORE_WRITTEN", "CONFIGURATION_MIXED", "REPETITIONS", "SEED_REUSED", "TASK_SET",
         "CACHE_EXCEEDS_TOKENS", "INCOMPARABLE", "DECISION_MISMATCH", "HELD_OUT_SELECTION", "SELECTION_BASIS")


class Refused(ValueError):
    """A record breaks a rule; `code` is one of CODES."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _refuse(ok: bool, code: str) -> None:
    if not ok:
        raise Refused(code)


# ---------------------------------------------------------------- canonical form and text (as the verdict ledger's)

def _integral(value) -> bool:
    if type(value) is int:
        return abs(value) <= MAX_INT
    return type(value) is float and math.isfinite(value) and value.is_integer() and abs(value) <= MAX_INT


def _normal(value):
    if type(value) is float:
        _refuse(_integral(value), "SHAPE")
        return int(value)
    if type(value) is list:
        return [_normal(v) for v in value]
    if type(value) is dict:
        return {k: _normal(v) for k, v in value.items()}
    return value


def canonical(value) -> bytes:
    """RFC 8785 (JCS) bytes of a record: keys sorted, no whitespace, UTF-8, integers without a fraction."""
    return json.dumps(_normal(value), sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def digest(value) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _no_constant(name):
    raise Refused("SHAPE")


def _members(pairs):
    names = [name for name, _ in pairs]
    _refuse(len(names) == len(set(names)), "SHAPE")
    return dict(pairs)


def parse(text):
    """Record text as I-JSON (RFC 7493): UTF-8, no duplicate member names, no NaN or infinity; anything else is SHAPE."""
    try:
        if isinstance(text, (bytes, bytearray)):
            text = bytes(text).decode("utf-8")
        text.encode("utf-8")
        return json.loads(text, object_pairs_hook=_members, parse_constant=_no_constant)
    except Refused:
        raise
    except (ValueError, TypeError, RecursionError) as exc:
        raise Refused("SHAPE") from exc


# ---------------------------------------------------------------- shape helpers

def _text(value, limit: int = 1024) -> bool:
    return (type(value) is str and 0 < len(value) <= limit
            and not any(0xD800 <= ord(c) <= 0xDFFF for c in value))


def _ident(value) -> bool:
    return type(value) is str and IDENT.match(value) is not None


def _digest_str(value) -> bool:
    return type(value) is str and DIGEST.match(value) is not None


def _int(value, low: int, high: int) -> bool:
    return _integral(value) and low <= value <= high


def _time(value) -> bool:
    """A UTC time `YYYY-MM-DDTHH:MM:SSZ` with field ranges checked (not the calendar); such strings order as the times do."""
    return type(value) is str and TIME.match(value) is not None


def _closed(value, keys, optional=()) -> bool:
    return type(value) is dict and set(keys) <= set(value) <= set(keys) | set(optional)


def _list(value, low: int = 0) -> bool:
    return type(value) is list and low <= len(value) <= MAX_ITEMS


def _unique(values) -> None:
    values = list(values)
    _refuse(len(values) == len(set(values)), "DUPLICATE_ID")


def _guarded(check):
    """Run one record check; anything malformed that slipped past the shape rules is SHAPE, never another exception."""
    try:
        return check()
    except Refused:
        raise
    except (KeyError, TypeError, AttributeError, IndexError, ValueError, UnicodeError, RecursionError) as exc:
        raise Refused("SHAPE") from exc


# ---------------------------------------------------------------- split declaration

def check_split(doc: dict) -> dict:
    """A split declaration: two non-empty, disjoint task sets (by task ID and by task digest), declared at a time."""
    def run():
        _refuse(_closed(doc, ("schemaVersion", "splitId", "suiteDigest", "declaredAt", "partitions"))
                and doc["schemaVersion"] == SPLIT_SCHEMA and _ident(doc["splitId"]) and _digest_str(doc["suiteDigest"])
                and _time(doc["declaredAt"]) and _closed(doc["partitions"], PARTITIONS), "SHAPE")
        for name in PARTITIONS:
            tasks = doc["partitions"][name]
            _refuse(_list(tasks) and all(_closed(t, ("taskId", "taskDigest")) and _ident(t["taskId"])
                                         and _digest_str(t["taskDigest"]) for t in tasks), "SHAPE")
        for name in PARTITIONS:
            _unique(t["taskId"] for t in doc["partitions"][name])
            _unique(t["taskDigest"] for t in doc["partitions"][name])
        _refuse(all(doc["partitions"][name] for name in PARTITIONS), "PARTITION_EMPTY")
        dev, held = (doc["partitions"][name] for name in PARTITIONS)
        _refuse(not ({t["taskId"] for t in dev} & {t["taskId"] for t in held})
                and not ({t["taskDigest"] for t in dev} & {t["taskDigest"] for t in held}), "PARTITION_OVERLAP")
        return {"digest": digest(doc), "tasks": {name: sorted(t["taskId"] for t in doc["partitions"][name])
                                                 for name in PARTITIONS}}
    return _guarded(run)


# ---------------------------------------------------------------- run manifest

def _configuration(value) -> bool:
    return (_closed(value, ("model", "harness", "budget", "agentCount"))
            and _closed(value["model"], ("id", "configurationDigest")) and _text(value["model"]["id"], 128)
            and _digest_str(value["model"]["configurationDigest"])
            and _closed(value["harness"], ("commit", "dirty")) and type(value["harness"]["commit"]) is str
            and COMMIT.match(value["harness"]["commit"]) is not None and type(value["harness"]["dirty"]) is bool
            and _closed(value["budget"], ("tokensPerTask", "costMicrosPerTask", "wallClockSecondsPerTask"))
            and _int(value["budget"]["tokensPerTask"], 1, MAX_INT) and _int(value["budget"]["costMicrosPerTask"], 0, MAX_INT)
            and _int(value["budget"]["wallClockSecondsPerTask"], 1, MAX_INT) and _int(value["agentCount"], 1, 1024))


LOCK_KEYS = ("specsDigest", "promptDigests", "toolSchemaDigests", "imageDigests", "dependencyLockDigests",
             "fixtureDigest", "datasetDigest", "evaluator", "environmentDigest")
LOCK_LISTS = (("promptDigests", 1), ("toolSchemaDigests", 0), ("imageDigests", 1), ("dependencyLockDigests", 1))


def _locks(value) -> bool:
    return (_closed(value, LOCK_KEYS)
            and all(_digest_str(value[k]) for k in ("specsDigest", "fixtureDigest", "datasetDigest", "environmentDigest"))
            and all(_list(value[k], low) and all(_digest_str(d) for d in value[k]) for k, low in LOCK_LISTS)
            and _closed(value["evaluator"], ("id", "version", "digest")) and _text(value["evaluator"]["id"], 128)
            and _text(value["evaluator"]["version"], 128) and _digest_str(value["evaluator"]["digest"]))


def _seed(value) -> bool:
    if type(value) is not dict or value.get("mode") not in SEED_MODES:
        return False
    if value["mode"] == "FIXED":
        return _closed(value, ("mode", "value")) and _int(value["value"], 0, MAX_INT)
    return _closed(value, ("mode", "statement")) and _text(value["statement"])


MANIFEST_KEYS = ("schemaVersion", "runId", "scopeDigest", "suiteDigest", "configuration", "locks", "seed", "execution",
                 "split", "repetition", "writtenAt", "startedAt", "ledgerDigest")


def check_manifest(doc: dict, splits: dict) -> dict:
    """A run manifest, written before its run: every lock present; the split declared no later than the manifest and the
    run started no earlier than the manifest. `splits` maps split-declaration digests to declarations."""
    def run():
        _refuse(_closed(doc, MANIFEST_KEYS) and doc["schemaVersion"] == MANIFEST_SCHEMA and _ident(doc["runId"])
                and _digest_str(doc["scopeDigest"]) and _digest_str(doc["suiteDigest"])
                and _configuration(doc["configuration"]) and _locks(doc["locks"]) and _seed(doc["seed"])
                and _closed(doc["execution"], ("cacheKeyDigest", "parallelism"))
                and _digest_str(doc["execution"]["cacheKeyDigest"]) and _int(doc["execution"]["parallelism"], 1, 1024)
                and _closed(doc["split"], ("declarationDigest", "partition"))
                and _digest_str(doc["split"]["declarationDigest"]) and doc["split"]["partition"] in PARTITIONS
                and _int(doc["repetition"], 1, 1000) and _time(doc["writtenAt"]) and _time(doc["startedAt"])
                and (doc["ledgerDigest"] is None or _digest_str(doc["ledgerDigest"])), "SHAPE")
        for key, _ in LOCK_LISTS:
            _unique(doc["locks"][key])
        split = splits.get(doc["split"]["declarationDigest"]) if type(splits) is dict else None
        _refuse(split is not None, "UNKNOWN_REFERENCE")
        facts = check_split(split)
        _refuse(facts["digest"] == doc["split"]["declarationDigest"], "UNKNOWN_REFERENCE")
        _refuse(split["suiteDigest"] == doc["suiteDigest"], "SPLIT_SUITE")
        _refuse(split["declaredAt"] <= doc["writtenAt"], "SPLIT_AFTER_RUN")
        _refuse(doc["writtenAt"] <= doc["startedAt"], "STARTED_BEFORE_WRITTEN")
        return {"digest": digest(doc), "dirty": doc["configuration"]["harness"]["dirty"]}
    return _guarded(run)


# ---------------------------------------------------------------- configuration-level evaluation record

RECORD_KEYS = ("schemaVersion", "recordId", "scopeDigest", "suiteDigest", "configuration", "split",
               "repetitionsDeclared", "runs")
RESULT_KEYS = ("taskId", "score", "tokensTotal", "cacheReadTokens", "costMicros")


def check_record(doc: dict, manifests: dict, splits: dict) -> dict:
    """One configuration on one suite and partition: every run's manifest is valid and names exactly this configuration,
    scope, suite, split, partition and repetition, with the same locks and seed mode as every other run; repetition
    indexes and prompt-cache keys are distinct; repetitions are within the declared k (>= 3); fixed seeds differ between
    runs; every run scores exactly the partition's tasks; cached tokens never exceed the total. A record with fewer runs
    than declared is valid and incomplete. `manifests` maps manifest digests to manifests."""
    def run():
        _refuse(_closed(doc, RECORD_KEYS) and doc["schemaVersion"] == RECORD_SCHEMA and _ident(doc["recordId"])
                and _digest_str(doc["scopeDigest"]) and _digest_str(doc["suiteDigest"])
                and _configuration(doc["configuration"])
                and _closed(doc["split"], ("declarationDigest", "partition"))
                and _digest_str(doc["split"]["declarationDigest"]) and doc["split"]["partition"] in PARTITIONS
                and _int(doc["repetitionsDeclared"], 1, 1000) and _list(doc["runs"]), "SHAPE")
        for r in doc["runs"]:
            _refuse(_closed(r, ("manifestDigest", "repetition", "results")) and _digest_str(r["manifestDigest"])
                    and _int(r["repetition"], 1, 1000) and _list(r["results"], 1)
                    and all(_closed(x, RESULT_KEYS) and _ident(x["taskId"]) and _int(x["score"], 0, MAX_SCORE)
                            and all(_int(x[k], 0, MAX_INT) for k in ("tokensTotal", "cacheReadTokens", "costMicros"))
                            for x in r["results"]), "SHAPE")
        _unique(r["manifestDigest"] for r in doc["runs"])
        _unique(r["repetition"] for r in doc["runs"])
        for r in doc["runs"]:
            _unique(x["taskId"] for x in r["results"])
        split = splits.get(doc["split"]["declarationDigest"]) if type(splits) is dict else None
        _refuse(split is not None and type(manifests) is dict
                and all(r["manifestDigest"] in manifests for r in doc["runs"]), "UNKNOWN_REFERENCE")
        split_facts = check_split(split)
        _refuse(split_facts["digest"] == doc["split"]["declarationDigest"], "UNKNOWN_REFERENCE")
        for r in doc["runs"]:
            manifest = manifests[r["manifestDigest"]]
            facts = check_manifest(manifest, splits)
            _refuse(facts["digest"] == r["manifestDigest"], "UNKNOWN_REFERENCE")
            first = manifests[doc["runs"][0]["manifestDigest"]]
            _refuse(manifest["configuration"] == doc["configuration"] and manifest["scopeDigest"] == doc["scopeDigest"]
                    and manifest["suiteDigest"] == doc["suiteDigest"] and manifest["split"] == doc["split"]
                    and manifest["repetition"] == r["repetition"] and manifest["locks"] == first["locks"]
                    and manifest["seed"]["mode"] == first["seed"]["mode"], "CONFIGURATION_MIXED")
        _unique(manifests[r["manifestDigest"]]["execution"]["cacheKeyDigest"] for r in doc["runs"])
        _refuse(doc["repetitionsDeclared"] >= MIN_REPETITIONS and len(doc["runs"]) <= doc["repetitionsDeclared"]
                and all(r["repetition"] <= doc["repetitionsDeclared"] for r in doc["runs"]), "REPETITIONS")
        fixed = [manifests[r["manifestDigest"]]["seed"]["value"] for r in doc["runs"]
                 if manifests[r["manifestDigest"]]["seed"]["mode"] == "FIXED"]
        _refuse(len(fixed) == len(set(fixed)), "SEED_REUSED")
        tasks = split_facts["tasks"][doc["split"]["partition"]]
        _refuse(all(sorted(x["taskId"] for x in r["results"]) == tasks for r in doc["runs"]), "TASK_SET")
        _refuse(all(x["cacheReadTokens"] <= x["tokensTotal"] for r in doc["runs"] for x in r["results"]),
                "CACHE_EXCEEDS_TOKENS")
        sums = {t: sum(x["score"] for r in doc["runs"] for x in r["results"] if x["taskId"] == t) for t in tasks}
        locks = manifests[doc["runs"][0]["manifestDigest"]]["locks"] if doc["runs"] else None
        tokens = sum(x["tokensTotal"] for r in doc["runs"] for x in r["results"])
        results = sum(len(r["results"]) for r in doc["runs"])
        return {"digest": digest(doc), "complete": len(doc["runs"]) == doc["repetitionsDeclared"],
                "dirty": doc["configuration"]["harness"]["dirty"], "runs": len(doc["runs"]), "tasks": tasks, "sums": sums,
                "comparableLocks": None if locks is None else {k: locks[k] for k in COMPARABLE_LOCKS},
                "tokensTotal": tokens, "tokensMeanPerTaskRun": tokens // results if results else 0}
    return _guarded(run)


# ---------------------------------------------------------------- the distribution gate

def critical(df: int) -> int:
    """The two-sided 95% critical value in thousandths for df >= 1 degrees of freedom: the value of the largest tabulated
    df not above it (conservative, see T_CRITICAL)."""
    value = T_CRITICAL[0][1]
    for tabulated, crit in T_CRITICAL:
        if df >= tabulated:
            value = crit
    return value


def _ceil_sqrt_ratio(x: int, y: int) -> int:
    """The smallest integer h >= 0 with h * h * y >= x (x >= 0, y > 0): ceil(sqrt(x / y))."""
    h = math.isqrt(x // y)
    while h * h * y < x:
        h += 1
    return h


def compare(baseline: dict, candidate: dict, tolerance_ppm: int) -> dict:
    """The decision on two checked records' facts (`check_record` results): UNRESOLVED when either is incomplete, dirty or
    has fewer than two tasks; otherwise the paired task-clustered interval of the per-task mean difference (candidate
    minus baseline) at the conservative 95% t critical value for n - 1 degrees of freedom. All arithmetic is integer:
    with k_b and k_c runs, the scaled per-task difference is D_t = k_b * sum_c(t) - k_c * sum_b(t) (in ppm / (k_b k_c)),
    T = sum D_t, Q = n * sum D_t^2 - T^2, c the critical value in thousandths and tol = tolerance * k_b * k_c. IMPROVED
    when L = T - n * tol > 0 and L^2 (n - 1) 10^6 > c^2 Q; REGRESSED when U = T + n * tol < 0 and U^2 (n - 1) 10^6 > c^2 Q;
    otherwise WITHIN_NOISE. nonInferior: U > 0 and U^2 (n - 1) 10^6 > c^2 Q (the lower bound above minus the tolerance).
    The arithmetic needs arbitrary-precision integers (c^2 Q exceeds 2^53 even for small suites); T and sum D_t^2 are not
    recorded, only the bounded statistics."""
    for facts in (baseline, candidate):
        if not facts["complete"]:
            return {"decision": "UNRESOLVED", "unresolvedReason": "INCOMPLETE", "statistics": None}
    if baseline["dirty"] or candidate["dirty"]:
        return {"decision": "UNRESOLVED", "unresolvedReason": "DIRTY_TREE", "statistics": None}
    tasks = baseline["tasks"]
    n = len(tasks)
    if n < 2:
        return {"decision": "UNRESOLVED", "unresolvedReason": "TOO_FEW_TASKS", "statistics": None}
    kb, kc = baseline["runs"], candidate["runs"]
    scale = kb * kc
    diffs = [kb * candidate["sums"][t] - kc * baseline["sums"][t] for t in tasks]
    total = sum(diffs)
    squares = sum(d * d for d in diffs)
    q = n * squares - total * total
    c = critical(n - 1)
    tol = tolerance_ppm * scale
    lower, upper = total - n * tol, total + n * tol
    if lower > 0 and lower * lower * (n - 1) * 10 ** 6 > c * c * q:
        decision = "IMPROVED"
    elif upper < 0 and upper * upper * (n - 1) * 10 ** 6 > c * c * q:
        decision = "REGRESSED"
    else:
        decision = "WITHIN_NOISE"
    # Non-inferiority: the interval's lower bound lies above minus the tolerance (the same test as IMPROVED, mirrored).
    non_inferior = upper > 0 and upper * upper * (n - 1) * 10 ** 6 > c * c * q
    statistics = {"tasks": n, "baselineRuns": kb, "candidateRuns": kc, "criticalThousandths": c,
                  "meanDifferencePpm": total // (n * scale),
                  "halfWidthPpm": _ceil_sqrt_ratio(c * c * q, (1000 * n * scale) ** 2 * (n - 1)),
                  "nonInferior": non_inferior}
    return {"decision": decision, "unresolvedReason": None, "statistics": statistics}


def h16_state(purpose: str, decision: str, non_inferior: bool) -> str:
    """The H16 evidence state a comparison supports. NON_REGRESSION: PASS when the candidate is non-inferior (IMPROVED, or
    WITHIN_NOISE with the lower bound above minus the tolerance), WARN for any other WITHIN_NOISE (inconclusive) and for
    UNRESOLVED, FAIL for REGRESSED. IMPROVEMENT: PASS only for IMPROVED, WARN for UNRESOLVED, FAIL otherwise."""
    if decision == "UNRESOLVED":
        return "WARN"
    if purpose == "IMPROVEMENT":
        return "PASS" if decision == "IMPROVED" else "FAIL"
    if decision == "REGRESSED":
        return "FAIL"
    return "PASS" if non_inferior else "WARN"


def _statistics(value) -> bool:
    if value is None:
        return True
    return (_closed(value, STATISTICS_KEYS) and _int(value["tasks"], 2, MAX_ITEMS)
            and _int(value["baselineRuns"], MIN_REPETITIONS, 1000) and _int(value["candidateRuns"], MIN_REPETITIONS, 1000)
            and _int(value["criticalThousandths"], 1000, 100000) and _int(value["meanDifferencePpm"], -MAX_SCORE, MAX_SCORE)
            and _int(value["halfWidthPpm"], 0, MAX_INT) and type(value["nonInferior"]) is bool)


COMPARISON_KEYS = ("schemaVersion", "comparisonId", "purpose", "baselineDigest", "candidateDigest", "tolerance",
                   "decision", "unresolvedReason", "statistics")


def check_comparison(doc: dict, records: dict, manifests: dict, splits: dict) -> dict:
    """A recorded distribution-gate comparison: both records valid and comparable (same scope, suite, split declaration
    and partition, the same evaluator, dataset, fixture and environment locks, two different records), and the recorded
    decision, reason and statistics exactly the model's.
    Returns the facts with the H16 evidence state for the comparison's purpose."""
    def run():
        _refuse(_closed(doc, COMPARISON_KEYS) and doc["schemaVersion"] == COMPARISON_SCHEMA
                and _ident(doc["comparisonId"]) and doc["purpose"] in PURPOSES
                and _digest_str(doc["baselineDigest"]) and _digest_str(doc["candidateDigest"])
                and _closed(doc["tolerance"], ("version", "ppm")) and _ident(doc["tolerance"]["version"])
                and _int(doc["tolerance"]["ppm"], 0, MAX_SCORE) and doc["decision"] in DECISIONS
                and (doc["unresolvedReason"] is None or doc["unresolvedReason"] in UNRESOLVED_REASONS)
                and _statistics(doc["statistics"]), "SHAPE")
        _refuse(type(records) is dict and doc["baselineDigest"] in records and doc["candidateDigest"] in records,
                "UNKNOWN_REFERENCE")
        base_doc, cand_doc = records[doc["baselineDigest"]], records[doc["candidateDigest"]]
        base, cand = check_record(base_doc, manifests, splits), check_record(cand_doc, manifests, splits)
        _refuse(base["digest"] == doc["baselineDigest"] and cand["digest"] == doc["candidateDigest"], "UNKNOWN_REFERENCE")
        _refuse(doc["baselineDigest"] != doc["candidateDigest"]
                and all(base_doc[k] == cand_doc[k] for k in ("scopeDigest", "suiteDigest", "split"))
                and (base["comparableLocks"] is None or cand["comparableLocks"] is None
                     or base["comparableLocks"] == cand["comparableLocks"]), "INCOMPARABLE")
        result = compare(base, cand, doc["tolerance"]["ppm"])
        _refuse({k: doc[k] for k in ("decision", "unresolvedReason", "statistics")} == result, "DECISION_MISMATCH")
        non_inferior = result["statistics"] is not None and result["statistics"]["nonInferior"]
        return {"digest": digest(doc), **result, "nonInferior": non_inferior,
                "h16EvidenceState": h16_state(doc["purpose"], result["decision"], non_inferior)}
    return _guarded(run)


# ---------------------------------------------------------------- selection

SELECTION_KEYS = ("schemaVersion", "selectionId", "candidates", "chosen", "basis")


def check_selection(doc: dict, comparisons: dict, records: dict, manifests: dict, splits: dict) -> dict:
    """A selection among candidate configurations: every candidate record and every record a basis comparison uses is a
    DEVELOPMENT record, none of whose tasks a valid declaration in the store holds out (by content digest in any suite, by
    task ID in the same suite; held-out scores are never selection input); the candidates are comparable as a comparison's
    records are (scope, suite, split and the evaluator, dataset, fixture and environment locks); the chosen record is a
    candidate; every basis comparison compares two candidates. It records the inputs of a choice; it does not justify the
    choice."""
    def run():
        _refuse(_closed(doc, SELECTION_KEYS) and doc["schemaVersion"] == SELECTION_SCHEMA and _ident(doc["selectionId"])
                and _list(doc["candidates"], 2) and all(_digest_str(d) for d in doc["candidates"])
                and _digest_str(doc["chosen"]) and _list(doc["basis"]) and all(_digest_str(d) for d in doc["basis"]),
                "SHAPE")
        _unique(doc["candidates"])
        _unique(doc["basis"])
        _refuse(type(records) is dict and type(comparisons) is dict and all(d in records for d in doc["candidates"])
                and all(d in comparisons for d in doc["basis"]), "UNKNOWN_REFERENCE")
        used = list(doc["candidates"])
        for d in doc["basis"]:
            facts = check_comparison(comparisons[d], records, manifests, splits)
            _refuse(facts["digest"] == d, "UNKNOWN_REFERENCE")
            used += [comparisons[d]["baselineDigest"], comparisons[d]["candidateDigest"]]
        for d in used:
            _refuse(check_record(records[d], manifests, splits)["digest"] == d, "UNKNOWN_REFERENCE")
        _refuse(all(records[d]["split"]["partition"] == "DEVELOPMENT" for d in used), "HELD_OUT_SELECTION")
        # Store-relative: no used record may score a task that a valid declaration in the store holds out, matched by
        # content digest in any suite and also by task ID in the same suite. Store entries that are not valid declarations
        # stored under their own digest are not declarations and are ignored. A hold-out declared later still counts.
        valid = []
        for key, entry in splits.items():
            try:
                if check_split(entry)["digest"] == key:
                    valid.append(entry)
            except Refused:
                continue
        held_digests = {t["taskDigest"] for v in valid for t in v["partitions"]["HELD_OUT"]}
        for d in used:
            split = splits[records[d]["split"]["declarationDigest"]]
            held_ids = {t["taskId"] for v in valid if v["suiteDigest"] == split["suiteDigest"] for t in v["partitions"]["HELD_OUT"]}
            dev = split["partitions"]["DEVELOPMENT"]
            _refuse(not ({t["taskDigest"] for t in dev} & held_digests) and not ({t["taskId"] for t in dev} & held_ids),
                    "HELD_OUT_SELECTION")
        first = records[doc["candidates"][0]]
        locks = [check_record(records[d], manifests, splits)["comparableLocks"] for d in doc["candidates"]]
        _refuse(all(records[d][k] == first[k] for d in doc["candidates"] for k in ("scopeDigest", "suiteDigest", "split"))
                and len({canonical(l) for l in locks if l is not None}) <= 1, "INCOMPARABLE")
        _refuse(doc["chosen"] in doc["candidates"] and set(used) <= set(doc["candidates"]), "SELECTION_BASIS")
        return {"digest": digest(doc), "chosen": doc["chosen"]}
    return _guarded(run)


if __name__ == "__main__":
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    vectors = json.loads((root / "architecture/run-manifest/vectors.json").read_bytes())
    stores = vectors["stores"]
    checks = {"split": lambda d: check_split(d),
              "manifest": lambda d: check_manifest(d, stores["splits"]),
              "record": lambda d: check_record(d, stores["manifests"], stores["splits"]),
              "comparison": lambda d: check_comparison(d, stores["records"], stores["manifests"], stores["splits"]),
              "selection": lambda d: check_selection(d, stores["comparisons"], stores["records"], stores["manifests"],
                                                     stores["splits"])}
    for row in vectors["cases"]:
        try:
            facts = checks[row["kind"]](row["document"])
            got = None
        except Refused as refusal:
            got, facts = refusal.code, None
        assert got == row["expect"], (row["id"], got, row["expect"])
        if facts is not None and "facts" in row:
            assert {k: facts[k] for k in row["facts"]} == row["facts"], row["id"]
    for row in vectors["texts"]:
        try:
            checks[row["kind"]](parse(row["text"]))
            got = None
        except Refused as refusal:
            got = refusal.code
        assert got == row["expect"], row["id"]
    for row in vectors["criticalValues"]:
        assert critical(row["df"]) == row["thousandths"], row
    print("run manifest vectors replay: %d cases, %d texts, %d critical values"
          % (len(vectors["cases"]), len(vectors["texts"]), len(vectors["criticalValues"])))
