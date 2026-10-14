#!/usr/bin/env python3
"""Research adoption v3 (architecture/research-adoption-v3/, RA-LICENSE-001): licence clarification and baseline recheck.

check(read) validates the two closed records through an injected byte reader:
- licences.json: the licence texts of BerriAI/litellm, pgvector/pgvector, langfuse/langfuse and Arize-ai/phoenix at a
  pinned commit, recorded by git blob id and SHA-256 only (the texts stay operator-side). Each text carries its SPDX
  identifier and the directories it governs; the parts, their licence sets and outcomes, each repository's outcome and
  ceiling and every scoped artifact's are recomputed here under the pinned licence policy 0.3.0, whose lists, precedence
  and set rules are read from the policy file itself;
- planned-baselines.json: the 29 planned baselines of the 2026-09 record (architecture/research-adoption.json, the
  repositories its mappings prefer, in its upstream order), each with its 2026-09 values copied exactly, the 2026-10-14
  re-check with a pinned HEAD commit, the derived changes and the policy outcome of the GitHub-reported identifier;
- the 2026-09 record, its map, the v2 crosswalk and the licence policy are bound by digest (they stay byte-identical);
- the records and README carry no personal data or local paths, and the README is exactly render(licences, baselines).
Data checks only: no imports beyond the standard library, no network, no execution authority.
"""
from __future__ import annotations

import hashlib
import json
import math
import re

OVERLAY_DIR = "architecture/research-adoption-v3/"
LICENCES_PATH = OVERLAY_DIR + "licences.json"
BASELINES_PATH = OVERLAY_DIR + "planned-baselines.json"
README_PATH = OVERLAY_DIR + "README.md"
V1_PATH = "architecture/research-adoption.json"
V1_SHA256 = "18dadbbe9aa29b69d18b9ded27e27f6057cf03b437190d14477b2c6908dbc5d5"
MAP_PATH = "docs/alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md"
MAP_SHA256 = "f6a891e8bdbcc579e60800773addd70ca29a2c4021c2dc95af62be93e91f061d"
V2_PATH = "architecture/research-adoption-v2/crosswalk.json"
V2_SHA256 = "e1b57c70a63f9b71994b2c25b4c786c9721f34ef34f08729ae6e9fc209010a75"
POLICY_PATH = "legal/third-party-license-policy.yaml"
POLICY_SHA256 = "fa3a4398acafc3960eaaae9f5396d4e96d91e6ff252b83f6c53e1f5f0d8a40d0"
META_BASE = "0d776f75bdca0844d4c6884a29c9fb82b3a61c78"
LICENCES_SCHEMA = "planeon.internal.research-adoption-licences/v3"
BASELINES_SCHEMA = "planeon.internal.research-adoption-baselines/v3"
MAX_BYTES = 1_048_576
MAX_DEPTH = 16

# legal/third-party-license-policy.yaml 0.3.0, restated; policy() reads the same lists from the pinned file and they must
# be equal. A licence set takes the highest-precedence outcome of its members (mixedLicenseSetRule); a member on no list
# is DENY_UNKNOWN_LICENSE (the policy's UNKNOWN) and an empty set DENY_MISSING_LICENSE.
DENIED = frozenset({"SSPL-1.0", "BUSL-1.1", "Elastic-2.0"})
PLANNED_UNRESOLVED = frozenset({"NOASSERTION"})
OPTIONAL_EXPLICIT_REVIEW = frozenset({"GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only", "LGPL-3.0-only",
                                      "LGPL-3.0-or-later", "Apache-2.0 AND LGPL-3.0-or-later",
                                      "Apache-2.0 AND LGPL-3.0-or-later AND MIT"})
OPEN_CONTENT = frozenset({"CC0-1.0", "CC-BY-4.0"})
ALLOWED_EXCEPTION_EXPRESSION = frozenset({"Apache-2.0 WITH LLVM-exception", "Apache-2.0 OR BSD-2-Clause",
                                          "Apache-2.0 OR BSD-3-Clause"})
DEFAULT_ALLOWED = frozenset({"Apache-2.0", "0BSD", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0",
                             "PostgreSQL", "PSF-2.0", "Unicode-3.0", "W3C-20150513"})
PRECEDENCE = ("DENIED", "UNKNOWN", "PLANNED_UNRESOLVED", "OPTIONAL_EXPLICIT_REVIEW", "OPEN_CONTENT",
              "ALLOWED_EXCEPTION_EXPRESSION", "DEFAULT_ALLOWED")
OUTCOMES = ("DENIED", "DENY_UNKNOWN_LICENSE", "PLANNED_UNRESOLVED", "OPTIONAL_EXPLICIT_REVIEW", "OPEN_CONTENT",
            "ALLOWED_EXCEPTION_EXPRESSION", "DEFAULT_ALLOWED")
REUSABLE = ("DEFAULT_ALLOWED", "ALLOWED_EXCEPTION_EXPRESSION")

REPOSITORIES = ("BerriAI/litellm", "pgvector/pgvector", "langfuse/langfuse", "Arize-ai/phoenix")
# The repositories the 2026-09 record carries and the two the v2 crosswalk added (its packet-time check).
PREVIOUS_RECORD = {"BerriAI/litellm": V1_PATH, "pgvector/pgvector": V1_PATH, "langfuse/langfuse": V2_PATH,
                   "Arize-ai/phoenix": V2_PATH}
FETCHED_TEXTS, FETCHED_BYTES, BASELINE_COUNT = 15, 75_125, 29
TOP_LICENCES = ("schemaVersion", "workItem", "metaPacketId", "metaBase", "evidenceClass", "checkedAt", "bindings",
                "boundaries", "decisions", "method", "rules", "repositories", "notes", "nonClaims")
TOP_BASELINES = ("schemaVersion", "workItem", "metaPacketId", "metaBase", "evidenceClass", "checkedAt", "source",
                 "baselines", "summary", "nonClaims")
BINDINGS = {"record": (V1_PATH, V1_SHA256), "map": (MAP_PATH, MAP_SHA256), "crosswalk": (V2_PATH, V2_SHA256),
            "licensePolicy": (POLICY_PATH, POLICY_SHA256)}
BOUNDARIES = ("publicContractChange", "policyChange", "catalogChange", "runtimeChange", "packetDispatch",
              "ratingChange", "licenceTextsPublished", "copyAuthorization", "networkAtValidation")
DECISION_IDS = ("Q-HO4-2", "Q-HO4-3", "Q-HO4-4", "Q-RL-AB", "USER-CHAT-AB", "Q-RL-LAYOUT", "Q-RL-C", "USER-CHAT-C")
STAGES = (("A", 62), ("A-RETRY", 1), ("B", 4), ("C", 15))
RULE_KEYS = ("scope", "aggregation", "ceiling", "scopedArtifact")
REPOSITORY_KEYS = ("repository", "url", "pinnedCommit", "headRef", "githubLicense", "checkedAt", "previous", "listing",
                   "licenceTexts", "otherNamedFiles", "parts", "outcome", "licenceCeiling", "scopedArtifacts")
TEXT_KEYS = ("path", "blob", "size", "sha256", "spdx", "evidence", "covers", "except", "scopeStatedBy", "fetched",
             "sameBlobAs")
PART_KEYS = ("directory", "licenceSet", "governedBy", "outcome")
ARTIFACT_KEYS = ("id", "directories", "licenceSet", "outcome", "licenceCeiling")
BASELINE_KEYS = ("repository", "url", "harnessIds", "previous", "current", "changes", "policyOutcome", "licenceCeiling",
                 "clarification")
PREVIOUS_KEYS = ("license", "stars", "pushedAt", "archived", "checkedAt")
CURRENT_KEYS = ("license", "stars", "pushedAt", "archived", "defaultBranch", "headRef", "headCommit", "checkedAt",
                "headCheckedAt")

HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
SPDX = re.compile(r"(?:LicenseRef-[A-Za-z0-9.-]+|[A-Za-z0-9][A-Za-z0-9.+-]*)\Z")
TIMESTAMP = re.compile(r"2026-10-14T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]Z\Z")
ANY_TIMESTAMP = re.compile(r"20[0-9]{2}-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]Z\Z")
# A tree path whose base name the Stage B listing kept: LICENSE*, LICENCE*, COPYING*, NOTICE*, case-insensitively.
NAMED = re.compile(r"(?:licen[cs]e|copying|notice)", re.I)
PATH = re.compile(r"(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\Z")
DIRECTORY = re.compile(r"(?:[A-Za-z0-9_.-]+/)*\Z")
# Personal data and local paths that must not appear anywhere in the public records or README.
HYGIENE = (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"),
           re.compile(r"\b[A-Za-z0-9._-]+ at [A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b(?![/\w-]|\.[A-Za-z0-9])", re.I),
           re.compile(r"[(\[{]\s*at\s*[)\]}]|[(\[{]\s*dot\s*[)\]}]|copyright \(c\)|\bet al\b", re.I),
           re.compile(r"/Users/|/home/|~/|/private/|/tmp/"))


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _float(text: str) -> float:
    value = float(text)
    require(math.isfinite(value), "nonfinite number")
    return value


def _json(raw: bytes):
    def pairs(items):
        keys = [key for key, _ in items]
        require(len(keys) == len(set(keys)), "duplicate key")
        return dict(items)

    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, "record size")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_float=_float,
                      parse_constant=lambda name: (_ for _ in ()).throw(ValueError("nonfinite number")))


def _bound_json(read, path: str, sha256: str, max_bytes: int = 4_194_304):
    raw = read(path)
    require(type(raw) is bytes and digest(raw) == sha256, "byte-identical predecessor: " + path)
    require(len(raw) <= max_bytes, "predecessor size")

    def pairs(items):
        keys = [key for key, _ in items]
        require(len(keys) == len(set(keys)), "duplicate key")
        return dict(items)
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_float=_float)


def _depth(value, level=0) -> None:
    require(level <= MAX_DEPTH, "record nesting")
    if type(value) is dict:
        for item in value.values():
            _depth(item, level + 1)
    elif type(value) is list:
        for item in value:
            _depth(item, level + 1)


def _strings(value):
    if type(value) is str:
        yield value
    elif type(value) is dict:
        for key, item in value.items():
            yield key
            yield from _strings(item)
    elif type(value) is list:
        for item in value:
            yield from _strings(item)


def _clean(text: str, message: str) -> None:
    require(not any(rule.search(text) for rule in HYGIENE), message)


def _text(value, message):
    require(type(value) is str and value.strip() == value and bool(value), message)


def _closed(value, keys, message):
    require(type(value) is dict and tuple(value) == tuple(keys), message)


def _int(value, message, minimum=0):
    require(type(value) is int and value >= minimum, message)


def _block(lines, header):
    """The lines under the unique line header, up to the next line indented no deeper."""
    require(lines.count(header) == 1, "policy key: " + header.strip())
    depth = len(header) - len(header.lstrip(" "))
    out = []
    for line in lines[lines.index(header) + 1:]:
        if line.strip() and len(line) - len(line.lstrip(" ")) <= depth:
            break
        out.append(line)
    return out


def _items(lines, header, prefix):
    return tuple(line[len(prefix):] for line in _block(lines, header) if line.startswith(prefix))


def policy(raw: bytes) -> dict:
    """The pinned policy's classification lists and evaluation rules, read line by line from its bytes."""
    lines = raw.decode("utf-8").split("\n")
    for line in ("policyVersion: 0.3.0", "  failClosed: true", "  expressionMatching: EXACT_SPDX_EXPRESSION",
                 "  allExpressionsMustBeClassified: true", "  unknownExpressionOutcome: DENY_UNKNOWN_LICENSE",
                 "  emptyLicenseSetOutcome: DENY_MISSING_LICENSE"):
        require(lines.count(line) == 1, "policy 0.3.0 evaluation rule: " + line.strip())
    require(sum(line.startswith("  mixedLicenseSetRule: Apply the highest-precedence outcome present") for line in lines)
            == 1, "policy 0.3.0 mixed licence set rule")
    return {"DENIED": frozenset(_items(lines, "deniedForDefaultDistribution:", "  - ")),
            "PLANNED_UNRESOLVED": frozenset(_items(lines, "plannedUnresolvedSpdx:", "  - ")),
            "OPTIONAL_EXPLICIT_REVIEW": frozenset(_items(lines, "optionalExplicitReview:", "  - ")),
            "OPEN_CONTENT": frozenset(_items(lines, "openContentSpdx:", "  - expression: ")),
            "ALLOWED_EXCEPTION_EXPRESSION": frozenset(_items(lines, "allowedExceptionExpressions:", "  - expression: ")),
            "DEFAULT_ALLOWED": frozenset(_items(lines, "defaultAllowedSpdx:", "  - ")),
            "precedence": _items(lines, "  precedence:", "    - ")}


def classify(spdx: str) -> str:
    """The pinned policy's outcome for one exact SPDX expression."""
    for outcome, members in (("DENIED", DENIED), ("PLANNED_UNRESOLVED", PLANNED_UNRESOLVED),
                             ("OPTIONAL_EXPLICIT_REVIEW", OPTIONAL_EXPLICIT_REVIEW), ("OPEN_CONTENT", OPEN_CONTENT),
                             ("ALLOWED_EXCEPTION_EXPRESSION", ALLOWED_EXCEPTION_EXPRESSION),
                             ("DEFAULT_ALLOWED", DEFAULT_ALLOWED)):
        if spdx in members:
            return outcome
    return "DENY_UNKNOWN_LICENSE"


def aggregate(licence_set) -> str:
    """A licence set's outcome: the highest-precedence outcome of its members; an empty set has no licence."""
    if not licence_set:
        return "DENY_MISSING_LICENSE"
    present = {classify(spdx) for spdx in licence_set}
    return next(outcome for outcome in OUTCOMES if outcome in present)


def ceiling(outcome: str) -> str:
    return "REUSE_AFTER_GATES" if outcome in REUSABLE else "DESIGN_REFERENCE_ONLY"


def directory_of(path: str) -> str:
    return path.rsplit("/", 1)[0] + "/" if "/" in path else ""


def governs(text: dict, directory: str) -> bool:
    """A text without a stated scope governs its own directory only (the nearest licence text); a stated scope covers
    every directory under its prefixes except the excluded ones, nested licence texts included."""
    if text["scopeStatedBy"] is None:
        return directory == directory_of(text["path"])
    return (any(directory.startswith(c) for c in text["covers"])
            and not any(directory.startswith(e) for e in text["except"]))


def parts(texts) -> list:
    rows = []
    for directory in sorted({c for text in texts for c in text["covers"]}):
        governing = [text for text in texts if governs(text, directory)]
        licence_set = sorted({text["spdx"] for text in governing})
        rows.append({"directory": directory, "licenceSet": licence_set,
                     "governedBy": [text["path"] for text in governing], "outcome": aggregate(licence_set)})
    return rows


def check(read) -> dict:
    try:
        return _check(read)
    except (KeyError, TypeError, AttributeError, IndexError, StopIteration, UnicodeDecodeError, json.JSONDecodeError,
            RecursionError, OSError) as exc:
        raise ValueError("malformed research adoption v3 record: %s" % type(exc).__name__) from None


def _check(read) -> dict:
    policy_raw = read(POLICY_PATH)
    require(type(policy_raw) is bytes and digest(policy_raw) == POLICY_SHA256, "byte-identical licence policy")
    lists = policy(policy_raw)
    require(lists == {"DENIED": DENIED, "PLANNED_UNRESOLVED": PLANNED_UNRESOLVED,
                      "OPTIONAL_EXPLICIT_REVIEW": OPTIONAL_EXPLICIT_REVIEW, "OPEN_CONTENT": OPEN_CONTENT,
                      "ALLOWED_EXCEPTION_EXPRESSION": ALLOWED_EXCEPTION_EXPRESSION, "DEFAULT_ALLOWED": DEFAULT_ALLOWED,
                      "precedence": PRECEDENCE}, "restated lists equal the pinned policy's")
    map_raw = read(MAP_PATH)
    require(type(map_raw) is bytes and digest(map_raw) == MAP_SHA256, "byte-identical 2026-09 map")
    v1 = _bound_json(read, V1_PATH, V1_SHA256)
    v2 = _bound_json(read, V2_PATH, V2_SHA256)
    lic = _json(read(LICENCES_PATH))
    base = _json(read(BASELINES_PATH))
    for record in (lic, base):
        _depth(record)
        for text in _strings(record):
            _clean(text, "no personal data in the public records")
    repositories = _check_licences(lic, v1, v2)
    summary = _check_baselines(base, v1, repositories)
    readme = read(README_PATH)
    require(type(readme) is bytes and readme.decode("utf-8") == render(lic, base), "README is render(records)")
    _clean(readme.decode("utf-8"), "no personal data in the README")
    summary["repositories"] = {row["repository"]: row["outcome"] for row in lic["repositories"]}
    return summary


def _header(x, keys, schema, message):
    require(type(x) is dict and tuple(x) == keys, message)
    require(x["schemaVersion"] == schema and x["workItem"] == "RA-LICENSE-001" and x["metaPacketId"] == "MET-ADOPT-004"
            and x["metaBase"] == META_BASE and x["evidenceClass"] == "META_PLANNING_ONLY"
            and x["checkedAt"] == "2026-10-14", "planning boundary")


def _check_licences(x, v1, v2) -> dict:
    _header(x, TOP_LICENCES, LICENCES_SCHEMA, "closed licence record keys in order")
    require(x["bindings"] == {key: {"path": path, "sha256": sha} for key, (path, sha) in BINDINGS.items()},
            "the 2026-09 record, its map, the v2 crosswalk and the policy bound by digest")
    require(x["boundaries"] == {key: False for key in BOUNDARIES}, "data only: every boundary closed")
    require(type(x["decisions"]) is list and [d.get("id") for d in x["decisions"] if type(d) is dict] == list(DECISION_IDS),
            "the owner's and the user's decisions in order")
    for row in x["decisions"]:
        _closed(row, ("id", "date", "selected", "by", "text"), "closed decision")
        require(row["date"] == "2026-10-14", "decision date")
        for key in ("selected", "by", "text"):
            _text(row[key], "decision text")
    method = x["method"]
    _closed(method, ("access", "stages", "rerun", "evidence"), "closed method")
    for key in ("access", "rerun", "evidence"):
        _text(method[key], "method text")
    require(type(method["stages"]) is list
            and [(s.get("stage"), s.get("requests")) for s in method["stages"] if type(s) is dict] == list(STAGES),
            "the approved stages and their request counts")
    for stage in method["stages"]:
        _closed(stage, ("stage", "requests", "decision", "what"), "closed stage")
        require(stage["decision"] in DECISION_IDS, "stage decision")
        _text(stage["what"], "stage text")
    _closed(x["rules"], RULE_KEYS, "closed rules")
    for key in RULE_KEYS:
        _text(x["rules"][key], "rule text")
    require(type(x["repositories"]) is list
            and [r.get("repository") for r in x["repositories"] if type(r) is dict] == list(REPOSITORIES),
            "the four repositories in order")
    fetched = {}
    for row in x["repositories"]:
        _check_repository(row, v1, v2, fetched)
    for row in x["repositories"]:
        for text in row["licenceTexts"]:
            if not text["fetched"]:
                ref = text["sameBlobAs"]
                _closed(ref, ("repository", "path"), "closed same-blob reference")
                source = fetched.get((ref["repository"], ref["path"]))
                require(source is not None and all(source[k] == text[k] for k in ("blob", "size", "sha256", "spdx", "evidence")),
                        "an unfetched text is the same blob as a fetched one")
    blobs = {(text["blob"]) for text in fetched.values()}
    require(len(fetched) == FETCHED_TEXTS == len(blobs)
            and sum(text["size"] for text in fetched.values()) == FETCHED_BYTES, "the 15 approved licence blobs")
    require(type(x["notes"]) is list and [n.get("id") for n in x["notes"] if type(n) is dict] == ["N-1", "N-2", "N-3", "N-4"],
            "carried notes")
    for note in x["notes"]:
        _closed(note, ("id", "repository", "subject", "text"), "closed note")
        require(note["repository"] in REPOSITORIES, "note repository")
        _text(note["subject"], "note subject")
        _text(note["text"], "note text")
    require(type(x["nonClaims"]) is list and len(x["nonClaims"]) == 5, "non-claims")
    for text in x["nonClaims"]:
        _text(text, "non-claim")
    return {row["repository"]: row for row in x["repositories"]}


def _check_repository(row, v1, v2, fetched) -> None:
    _closed(row, REPOSITORY_KEYS, "closed repository keys in order")
    name = row["repository"]
    require(row["url"] == "https://github.com/" + name and HEX40.match(row["pinnedCommit"])
            and re.fullmatch(r"refs/heads/[A-Za-z0-9_.-]+", row["headRef"]) and TIMESTAMP.match(row["checkedAt"])
            and row["githubLicense"] == "NOASSERTION", "pinned repository: " + name)
    previous = row["previous"]
    _closed(previous, ("record", "githubLicense", "policyOutcome", "licenceCeiling"), "closed previous state")
    if PREVIOUS_RECORD[name] == V1_PATH:
        prior = next(u for u in v1["upstreams"] if u["repository"] == name)["license"]
    else:
        prior = next(u for u in v2["upstreams"] if u["repository"] == name)["packetCheck"]["license"]
    require(previous == {"record": PREVIOUS_RECORD[name], "githubLicense": prior, "policyOutcome": classify(prior),
                         "licenceCeiling": ceiling(classify(prior))}, "previous state from the bound record: " + name)
    listing = row["listing"]
    _closed(listing, ("checkedAt", "entries", "truncated"), "closed listing")
    require(TIMESTAMP.match(listing["checkedAt"]) and listing["truncated"] is False, "complete tree listing: " + name)
    _int(listing["entries"], "tree entries", 1)
    texts = row["licenceTexts"]
    require(type(texts) is list and texts and [t.get("path") for t in texts if type(t) is dict]
            == sorted({t.get("path") for t in texts if type(t) is dict}), "licence texts sorted by path: " + name)
    paths = {t["path"] for t in texts}
    for text in texts:
        _closed(text, TEXT_KEYS, "closed licence text")
        path = text["path"]
        require(PATH.match(path) and ".." not in path.split("/") and NAMED.match(path.rsplit("/", 1)[-1]),
                "licence text path: " + path)
        require(HEX40.match(text["blob"]) and HEX64.match(text["sha256"]) and SPDX.match(text["spdx"]), "pinned text")
        _int(text["size"], "text size", 1)
        _text(text["evidence"], "identification evidence")
        for key in ("covers", "except"):
            value = text[key]
            require(type(value) is list and value == sorted(set(value))
                    and all(type(d) is str and DIRECTORY.match(d) for d in value), "scope prefixes")
        if text["scopeStatedBy"] is None:
            require(text["covers"] == [directory_of(path)] and text["except"] == [], "a text governs its directory")
        else:
            require(text["scopeStatedBy"] in paths and text["covers"]
                    and all(any(e.startswith(c) and e != c for c in text["covers"]) for e in text["except"]),
                    "a stated scope names its text and excludes only covered directories")
        if text["fetched"] is True:
            require(text["sameBlobAs"] is None, "a fetched text is its own blob")
            fetched[(name, path)] = text
        else:
            require(text["fetched"] is False, "fetched flag")
    for text in texts:
        if text["scopeStatedBy"] is not None:
            stater = next(t for t in texts if t["path"] == text["scopeStatedBy"])
            require(stater["fetched"] is True and stater["scopeStatedBy"] == stater["path"],
                    "a scope is stated by a fetched text that states its own")
    others = row["otherNamedFiles"]
    require(type(others) is list and [o.get("path") for o in others if type(o) is dict]
            == sorted({o.get("path") for o in others if type(o) is dict}), "other named files sorted")
    for other in others:
        _closed(other, ("path", "blob", "size"), "closed named file")
        require(PATH.match(other["path"]) and NAMED.match(other["path"].rsplit("/", 1)[-1])
                and other["path"] not in paths and HEX40.match(other["blob"]), "named file not a licence text")
        _int(other["size"], "named file size", 1)
    derived = parts(texts)
    require(row["parts"] == derived, "parts recomputed from the texts: " + name)
    directories = {part["directory"] for part in derived}
    require(all(part["licenceSet"] for part in derived)
            and all(e in directories for text in texts for e in text["except"]),
            "every part has a licence and every excluded directory is a part: " + name)
    every = sorted({spdx for part in derived for spdx in part["licenceSet"]})
    require(row["outcome"] == aggregate(every) and row["licenceCeiling"] == ceiling(row["outcome"]),
            "repository outcome: the policy's aggregate over every part: " + name)
    by_directory = {part["directory"]: part for part in derived}
    artifacts = row["scopedArtifacts"]
    require(type(artifacts) is list and len({a.get("id") for a in artifacts if type(a) is dict}) == len(artifacts),
            "unique scoped artifacts")
    for artifact in artifacts:
        _closed(artifact, ARTIFACT_KEYS, "closed scoped artifact")
        _text(artifact["id"], "artifact id")
        dirs = artifact["directories"]
        require(type(dirs) is list and dirs and dirs == sorted(set(dirs)) and set(dirs) < set(by_directory),
                "a scoped artifact is a proper subset of the parts")
        licence_set = sorted({spdx for d in dirs for spdx in by_directory[d]["licenceSet"]})
        require(artifact["licenceSet"] == licence_set and artifact["outcome"] == aggregate(licence_set)
                and artifact["licenceCeiling"] == ceiling(artifact["outcome"]), "scoped artifact outcome: " + artifact["id"])


def _check_baselines(x, v1, repositories) -> dict:
    _header(x, TOP_BASELINES, BASELINES_SCHEMA, "closed baseline record keys in order")
    preferred = {repo for mapping in v1["mappings"] for repo in mapping["preferredUpstreams"]}
    expected = [u for u in v1["upstreams"] if u["repository"] in preferred]
    require(len(expected) == BASELINE_COUNT, "29 planned baselines")
    _closed(x["source"], ("path", "sha256", "selection"), "closed source")
    require(x["source"]["path"] == V1_PATH and x["source"]["sha256"] == V1_SHA256, "baselines from the bound record")
    _text(x["source"]["selection"], "selection text")
    rows = x["baselines"]
    require(type(rows) is list and [r.get("repository") for r in rows if type(r) is dict]
            == [u["repository"] for u in expected], "the planned baselines in the record's order")
    changed = {"license": 0, "archived": 0}
    outcomes = {}
    for row, prior in zip(rows, expected):
        name = row["repository"]
        _closed(row, BASELINE_KEYS, "closed baseline keys in order")
        require(REPO.match(name) and row["url"] == "https://github.com/" + name, "baseline url")
        require(row["harnessIds"] == [m["harnessId"] for m in v1["mappings"] if name in m["preferredUpstreams"]],
                "harnesses from the bound record's mappings")
        require(row["previous"] == {key: prior[key] for key in PREVIOUS_KEYS}, "2026-09 values copied exactly: " + name)
        current = row["current"]
        _closed(current, CURRENT_KEYS, "closed current values")
        require(type(current["license"]) is str and SPDX.match(current["license"]) and type(current["archived"]) is bool
                and ANY_TIMESTAMP.match(current["pushedAt"]) and current["headRef"] == "refs/heads/" + current["defaultBranch"]
                and HEX40.match(current["headCommit"]) and TIMESTAMP.match(current["checkedAt"])
                and TIMESTAMP.match(current["headCheckedAt"]), "re-checked values: " + name)
        _int(current["stars"], "stars")
        require(row["changes"] == {"license": current["license"] != prior["license"],
                                   "archived": current["archived"] != prior["archived"],
                                   "stars": current["stars"] - prior["stars"]}, "derived changes: " + name)
        changed["license"] += row["changes"]["license"]
        changed["archived"] += row["changes"]["archived"]
        require(row["policyOutcome"] == classify(current["license"])
                and row["licenceCeiling"] == ceiling(row["policyOutcome"]), "outcome of the reported identifier: " + name)
        outcomes[row["policyOutcome"]] = outcomes.get(row["policyOutcome"], 0) + 1
        clarified = repositories.get(name)
        if clarified is None:
            require(row["clarification"] is None, "no clarification: " + name)
        else:
            require(clarified["pinnedCommit"] == current["headCommit"] and clarified["checkedAt"] == current["checkedAt"]
                    and row["clarification"] == {"record": LICENCES_PATH, "outcome": clarified["outcome"],
                                                 "licenceCeiling": clarified["licenceCeiling"],
                                                 "scopedArtifacts": len(clarified["scopedArtifacts"])},
                    "the clarification is the licence record's: " + name)
    summary = {"baselines": len(rows), "licenceChanged": changed["license"], "archivedChanged": changed["archived"],
               "archived": sum(row["current"]["archived"] for row in rows),
               "policyOutcomes": dict(sorted(outcomes.items())),
               "clarified": sum(row["clarification"] is not None for row in rows)}
    require(x["summary"] == summary, "summary recomputed")
    require(type(x["nonClaims"]) is list and len(x["nonClaims"]) == 2, "baseline non-claims")
    for text in x["nonClaims"]:
        _text(text, "non-claim")
    return dict(summary)


def _cell(text) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _set(licence_set) -> str:
    return ", ".join(licence_set) if licence_set else "(none)"


def _dir(directory: str) -> str:
    return "`%s`" % directory if directory else "(repository root)"


def render(lic: dict, base: dict) -> str:
    """The generated README for both records."""
    out = ["# Research adoption v3: licence clarification and planned-baseline recheck", "",
           "Generated by `scripts/research_adoption_v3.py` (render); do not edit by hand. Work item %s, packet %s, "
           "checked %s, evidence class %s." % (lic["workItem"], lic["metaPacketId"], lic["checkedAt"], lic["evidenceClass"]),
           "", "The 2026-09 record, its map, the v2 crosswalk and the licence policy stay byte-identical:", ""]
    for key, value in lic["bindings"].items():
        out.append("- %s: `%s` (sha256 `%s`)" % (key, value["path"], value["sha256"]))
    out += ["", "## Decisions", "", "| ID | Date | Selected | By | Text |", "|---|---|---|---|---|"]
    for row in lic["decisions"]:
        out.append("| %s | %s | %s | %s | %s |" % tuple(_cell(row[k]) for k in ("id", "date", "selected", "by", "text")))
    out += ["", "## Method", "", lic["method"]["access"], "", "| Stage | Requests | Decision | What |", "|---|---|---|---|"]
    for stage in lic["method"]["stages"]:
        out.append("| %s | %d | %s | %s |" % (stage["stage"], stage["requests"], stage["decision"], _cell(stage["what"])))
    out += ["", lic["method"]["rerun"], "", lic["method"]["evidence"], "", "## Rules", ""]
    for key in RULE_KEYS:
        out.append("- %s: %s" % (key, lic["rules"][key]))
    out += ["", "## Repositories", "", "| Repository | Pinned commit | Previous | Outcome | Ceiling | Scoped artifacts |",
            "|---|---|---|---|---|---|"]
    for row in lic["repositories"]:
        out.append("| %s | `%s` | %s (%s) | %s | %s | %d |" % (
            row["repository"], row["pinnedCommit"][:12], row["previous"]["policyOutcome"], row["previous"]["githubLicense"],
            row["outcome"], row["licenceCeiling"], len(row["scopedArtifacts"])))
    for row in lic["repositories"]:
        out += ["", "### %s" % row["repository"], "",
                "Commit `%s` (%s), GitHub licence %s, checked %s; tree listing %s, %d entries, not truncated." % (
                    row["pinnedCommit"], row["headRef"], row["githubLicense"], row["checkedAt"], row["listing"]["checkedAt"],
                    row["listing"]["entries"]),
                "", "| Licence text | Blob | Size | SHA-256 | SPDX | Governs | Except | Scope stated by | Fetched |",
                "|---|---|---|---|---|---|---|---|---|"]
        for text in row["licenceTexts"]:
            fetched = "yes" if text["fetched"] else "same blob as %s `%s`" % (text["sameBlobAs"]["repository"],
                                                                          text["sameBlobAs"]["path"])
            out.append("| `%s` | `%s` | %d | `%s` | %s | %s | %s | %s | %s |" % (
                text["path"], text["blob"][:12], text["size"], text["sha256"][:16], text["spdx"],
                ", ".join(_dir(d) for d in text["covers"]), ", ".join(_dir(d) for d in text["except"]) or "-",
                "`%s`" % text["scopeStatedBy"] if text["scopeStatedBy"] else "(own directory)", fetched))
        out += ["", "Identification: " + "; ".join("`%s`: %s" % (t["path"], t["evidence"]) for t in row["licenceTexts"]
                                                  if t["fetched"]) + "."]
        if row["otherNamedFiles"]:
            out += ["", "Named like a licence file but not a licence text (not fetched): " + ", ".join(
                "`%s`" % other["path"] for other in row["otherNamedFiles"]) + "."]
        out += ["", "| Part | Licence set | Governed by | Outcome |", "|---|---|---|---|"]
        for part in row["parts"]:
            out.append("| %s | %s | %s | %s |" % (_dir(part["directory"]), _set(part["licenceSet"]),
                                                  ", ".join("`%s`" % p for p in part["governedBy"]), part["outcome"]))
        out += ["", "Repository outcome: %s, ceiling %s." % (row["outcome"], row["licenceCeiling"])]
        if row["scopedArtifacts"]:
            out += ["", "| Scoped artifact | Parts | Licence set | Outcome | Ceiling |", "|---|---|---|---|---|"]
            for artifact in row["scopedArtifacts"]:
                out.append("| %s | %s | %s | %s | %s |" % (artifact["id"], ", ".join(_dir(d) for d in artifact["directories"]),
                                                           _set(artifact["licenceSet"]), artifact["outcome"],
                                                           artifact["licenceCeiling"]))
    out += ["", "## Carried notes", ""]
    for note in lic["notes"]:
        out.append("- %s (%s, %s): %s" % (note["id"], note["repository"], note["subject"], note["text"]))
    out += ["", "## Planned baselines", "", "Source: `%s` (sha256 `%s`); %s" % (
        base["source"]["path"], base["source"]["sha256"], base["source"]["selection"]), "",
            "| Repository | Licence (2026-09 -> now) | Stars | Last push | Archived | HEAD | Outcome | Ceiling | Clarified |",
            "|---|---|---|---|---|---|---|---|---|"]
    for row in base["baselines"]:
        prev, cur = row["previous"], row["current"]
        clarified = "-" if row["clarification"] is None else "%s, %s" % (row["clarification"]["outcome"],
                                                                         row["clarification"]["licenceCeiling"])
        out.append("| %s | %s -> %s | %d -> %d (%+d) | %s | %s | `%s` (%s) | %s | %s | %s |" % (
            row["repository"], prev["license"], cur["license"], prev["stars"], cur["stars"], row["changes"]["stars"],
            cur["pushedAt"], "yes" if cur["archived"] else "no", cur["headCommit"][:12], cur["headRef"],
            row["policyOutcome"], row["licenceCeiling"], clarified))
    summary = base["summary"]
    out += ["", "Summary: %d baselines; licence changed %d, archived changed %d, archived %d; outcomes %s; clarified %d." % (
        summary["baselines"], summary["licenceChanged"], summary["archivedChanged"], summary["archived"],
        ", ".join("%s %d" % item for item in summary["policyOutcomes"].items()), summary["clarified"]),
            "", "## Non-claims", ""]
    for text in lic["nonClaims"] + base["nonClaims"]:
        out.append("- " + text)
    return "\n".join(out) + "\n"
