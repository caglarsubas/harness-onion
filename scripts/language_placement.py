#!/usr/bin/env python3
"""Language placement v1 (MET-GOV-004, LANG-PLACEMENT-ADR-001): the minimal checker of ADR 0010's data.

`architecture/language-placement.json` places the 13 repositories, the 28 deployables of `architecture/services.yaml`
and the rows outside that catalogue on a planned language. Each row is tied by line digest to the spans of the
repository plans (and the alpha-2 amendments) that state it. The data also lists the exceptions under the owner's
LANG-D2 (b). `docs/adr/0010-language-placement.md` carries the policy text, LANG-D2 (a), and the four tables this
checker renders. Every enum and every expected value is a constant below (binding build rule BR-GOV4-1), so the data
carries no list of its own. The ADR decides no deployable's language beyond what the plans state.

Rules, in order; the first rule broken is reported with its id:
  R1 shape: closed objects and member types; every enum value is in its constant; the parse rules of `strict()`.
  R2 catalogues and policy: each catalogue's sha256 equals the head bytes; services.yaml's ids are unique and as many
     as its counts.total; repositories.yaml's ids are unique and 13; policySha256 and the ADR's policy line are
     POLICY_SHA256.
  R3 deployables: exactly services.yaml's ids, each once; ownerRepository and kind as catalogued; (status, plane,
     planeSource, plannedLanguage) equal EXPECTED[id].
  R4 repositories: exactly repositories.yaml's ids and names; the plan docs/repositories/NN-<lowercased name>.md gives
     rNumber RNN and the first span's path; languages equal REPO_LANGUAGES[id].
  R5 sources: every span is located by its content: some contiguous block of exactly last - first + 1 whole lines,
     anywhere in its file at the head, has the span's sha256 and carries its evidence (`lines` are the base position,
     for display only: a shift is accepted, a changed text is refused); a deployable's evidence holds its id token
     and its language token; a repository's spans carry each of its languages' tokens; every toolchain string occurs
     verbatim in one of its row's located spans.
  R6 outside the catalogue: exactly OUTSIDE_EXPECTED's ids, each with its (ownerRepository, plannedLanguage), whose
     spans carry its language token.
  R7 exceptions: one row per PENDING_HOTPATH_DECISION or CONTROL_LOOP_TO_BE_CONFIRMED deployable and none otherwise,
     owned by the deployable's repository and implementationOwnership packet, with GO as the default, the deployable's
     planned language, and evidence that begins PENDING: and names LANG-HOTPATH-DECISION-001 or the owning packet.
  R8 tables: each of the ADR's four table blocks equals this checker's rendering of the data's rows.

Usage (repository root):
  python3 scripts/language_placement.py check [--root DIR]     exit 0 accepted, 1 refused, 2 usage

The catalogues are read through scripts/safe_yaml.py (MON-LANG-2); standard library otherwise.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sys
from pathlib import Path
from typing import Any

try:
    from safe_yaml import safe_load
except ImportError:
    from scripts.safe_yaml import safe_load

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "planeon.internal.language-placement/v1"
DATA_PATH = "architecture/language-placement.json"
ADR_PATH = "docs/adr/0010-language-placement.md"
SERVICES_PATH = "architecture/services.yaml"
REPOSITORIES_PATH = "architecture/repositories.yaml"
CATALOGUES = (SERVICES_PATH, REPOSITORIES_PATH)
PLANS_DIR = "docs/repositories"
REPOSITORY_COUNT = 13
# The sha256 of the UTF-8 bytes of LANG-D2 (a), 1,051 characters, without a line feed (owner LANG-D2; D2-2).
POLICY_SHA256 = "4b0a8a4b9e043823cfa884bdb883ae5b8f796877ead7bdbc413b318082fbc441"
POLICY_BEGIN = "<!-- language-policy:begin -->"
POLICY_END = "<!-- language-policy:end -->"
# Integers beyond this magnitude are refused when parsed (as in scripts/lab_run_plan.py).
INTEGER_LIMIT = 10 ** 12

# ---------------------------------------------------------------- the closed constants (Q-GOV4-3; BR-GOV4-1)

LANGUAGES = ("PYTHON", "GO", "RUST", "TYPESCRIPT", "UPSTREAM_OWN")
PLANES = ("CONTROL", "DATA", "UNSTATED")
STATUSES = ("AS_PLANNED", "PENDING_HOTPATH_DECISION", "CONTROL_LOOP_TO_BE_CONFIRMED", "NO_STATED_DEFAULT")
PLANE_SOURCES = ("KIND_RULE", "OWNER_LANG_D2", "NOT_STATED")
EXCEPTION_STATUSES = ("PENDING_HOTPATH_DECISION", "CONTROL_LOOP_TO_BE_CONFIRMED")
# LANG-D2 (a)'s default for gateways, protocol mediation, tool dispatch and control loops.
DEFAULT_LANGUAGE = "GO"
HOTPATH_ITEM = "LANG-HOTPATH-DECISION-001"
PENDING_PREFIX = "PENDING:"
# A language's evidence tokens; UPSTREAM_OWN is the only multi-token entry (any one of them).
LANG_TOKEN = {"PYTHON": ("Python",), "GO": ("Go 1.26.7",), "RUST": ("Rust",), "TYPESCRIPT": ("TypeScript",),
              "UPSTREAM_OWN": ("upstream", "OSS implementation")}
# A deployable's id token is `<id>`, except these closed aliases.
ALIAS = {"operator": "`mas-harness-operator`", "otel-collector": "OTel Collector"}

_AS_PLANNED_PYTHON = ("AS_PLANNED", "UNSTATED", "NOT_STATED", "PYTHON")
_NO_DEFAULT_PYTHON = ("NO_STATED_DEFAULT", "UNSTATED", "NOT_STATED", "PYTHON")
_PENDING_DATA = ("PENDING_HOTPATH_DECISION", "DATA", "KIND_RULE", "PYTHON")
# Each deployable, in services.yaml's order: (status, plane, planeSource, plannedLanguage) (design section 5).
EXPECTED = {
    "bundle-verifier": ("AS_PLANNED", "UNSTATED", "NOT_STATED", "GO"),
    "otel-collector": ("AS_PLANNED", "UNSTATED", "NOT_STATED", "UPSTREAM_OWN"),
    "operator": ("AS_PLANNED", "CONTROL", "OWNER_LANG_D2", "GO"),
    "policy-decision": _NO_DEFAULT_PYTHON,
    "sandbox-runner": _NO_DEFAULT_PYTHON,
    "fleet-sync-agent": ("AS_PLANNED", "CONTROL", "KIND_RULE", "GO"),
    "guardrail-service": _AS_PLANNED_PYTHON,
    "usage-ledger": _NO_DEFAULT_PYTHON,
    "governance-service": _NO_DEFAULT_PYTHON,
    "domain-service": _NO_DEFAULT_PYTHON,
    "registry-service": _NO_DEFAULT_PYTHON,
    "inference-api": _AS_PLANNED_PYTHON,
    "connector-controller": ("CONTROL_LOOP_TO_BE_CONFIRMED", "UNSTATED", "NOT_STATED", "PYTHON"),
    "memory-service": _AS_PLANNED_PYTHON,
    "control-web": ("AS_PLANNED", "UNSTATED", "NOT_STATED", "TYPESCRIPT"),
    "ingest-worker": _NO_DEFAULT_PYTHON,
    "retrieval-service": _AS_PLANNED_PYTHON,
    "protocol-gateway": _PENDING_DATA,
    "evidence-service": _AS_PLANNED_PYTHON,
    "profile-compiler-worker": _NO_DEFAULT_PYTHON,
    "index-worker": _AS_PLANNED_PYTHON,
    "orchestration-api": _AS_PLANNED_PYTHON,
    "decision-service": _AS_PLANNED_PYTHON,
    "assurance-worker": _AS_PLANNED_PYTHON,
    "tool-broker": ("PENDING_HOTPATH_DECISION", "UNSTATED", "NOT_STATED", "PYTHON"),
    "orchestration-worker": _AS_PLANNED_PYTHON,
    "ai-gateway": _PENDING_DATA,
    "experience-gateway": _PENDING_DATA,
}
# Each row outside the catalogue: (ownerRepository, plannedLanguage).
OUTSIDE_EXPECTED = {
    "reference-channel-ui": ("mas-harness-runtime-plane", "TYPESCRIPT"),
    "model-backends": ("mas-harness-model-plane", "UPSTREAM_OWN"),
    "native-host-enforcement-roles": ("mas-harness-operator", "RUST"),
    "r12-native-probes": ("mas-harness-conformance-labs", "RUST"),
    "typescript-sdk": ("mas-harness-sdks", "TYPESCRIPT"),
}
# Each repository, in repositories.yaml's order: its exact language set.
REPO_LANGUAGES = {
    "harness-engineering": ("PYTHON",),
    "contracts": ("PYTHON",),
    "sdks": ("PYTHON", "TYPESCRIPT"),
    "industry-packs": ("PYTHON",),
    "control-plane": ("PYTHON", "TYPESCRIPT"),
    "runtime-plane": ("PYTHON", "TYPESCRIPT"),
    "model-plane": ("PYTHON",),
    "knowledge-plane": ("PYTHON",),
    "execution-plane": ("PYTHON",),
    "trust-plane": ("PYTHON",),
    "operator": ("GO", "RUST"),
    "distribution": ("PYTHON",),
    "conformance-labs": ("PYTHON", "RUST"),
}

TOP = ("schemaVersion", "adr", "policySha256", "catalogues", "repositories", "deployables", "outsideCatalogue",
       "exceptions")
REPOSITORY_MEMBERS = ("id", "name", "rNumber", "languages", "toolchain", "sources")
DEPLOYABLE_MEMBERS = ("id", "ownerRepository", "kind", "plannedLanguage", "toolchain", "plane", "planeSource", "status",
                      "source")
OUTSIDE_MEMBERS = ("id", "ownerRepository", "plannedLanguage", "sources")
EXCEPTION_MEMBERS = ("deployable", "status", "defaultLanguage", "plannedLanguage", "owner", "evidence", "reviewTrigger")
SPAN_MEMBERS = ("path", "lines", "sha256", "evidence")
HEX64 = re.compile(r"[0-9a-f]{64}")
R_NUMBER = re.compile(r"R[0-9]{2}")
REPO_PATH = re.compile(r"(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+")
PLAN_NAME = re.compile(r"([0-9]{2})-(.+)\.md")
TABLES = ("repositories", "deployables", "outsideCatalogue", "exceptions")
TABLE_TITLES = {"repositories": "Repositories", "deployables": "Deployables (architecture/services.yaml)",
                "outsideCatalogue": "Outside the catalogue", "exceptions": "Exceptions (LANG-D2 (b))"}


class Refusal(ValueError):
    """The data, the ADR or a source breaks a rule; `rule` is R1 to R8."""

    def __init__(self, rule: str, message: str):
        super().__init__(rule + ": " + message)
        self.rule = rule


def _refuse(ok: bool, rule: str, message: str) -> None:
    if not ok:
        raise Refusal(rule, message)


# ---------------------------------------------------------------- the parse rules, copied from scripts/lab_run_plan.py
# `require`, `canonical` and `strict` are LAB-RUNPLAN-001's (scripts/lab_run_plan.py), copied verbatim rather than
# imported (design D1-6): UTF-8 without a byte-order mark; duplicate keys, non-finite numbers, integral floats,
# oversized integers and lone surrogates refused.

def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical(value: Any) -> bytes:
    """The canonical JSON bytes a plan's sha256 is taken over: sorted keys, no whitespace, UTF-8. Integral numbers are
    integers (a float with an integral value is refused), so each plan has one canonical form."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def strict(raw: bytes) -> Any:
    """UTF-8 JSON without a byte-order mark; duplicate keys, non-finite numbers, integral floats, oversized integers and
    lone surrogates refused."""
    def pairs(items: list) -> dict:
        value: dict = {}
        for key, item in items:
            require(key not in value, "duplicate key " + key)
            value[key] = item
        return value

    def constant(name: str) -> Any:
        raise ValueError("non-finite number " + name)

    def number(text: str) -> float:
        value = float(text)
        require(math.isfinite(value), "non-finite number " + text)
        require(not value.is_integer(), "an integral number is written without a decimal point or exponent: " + text)
        return value

    def integer(text: str) -> int:
        require(len(text.lstrip("-")) <= 13 and abs(int(text)) <= INTEGER_LIMIT, "integer out of range")
        return int(text)

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("a document is UTF-8 without a byte-order mark") from None
    require(not text.startswith("﻿"), "a document is UTF-8 without a byte-order mark")
    value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant, parse_float=number, parse_int=integer)
    try:
        canonical(value)
    except UnicodeEncodeError:
        raise ValueError("a string is not valid Unicode (a lone surrogate)") from None
    return value


# ---------------------------------------------------------------- reading

def _read(root: Path, overlay: dict, rel: str, rule: str) -> bytes:
    """The bytes at `rel` in the tree, or the overlay's bytes for it (in-memory checks)."""
    if rel in overlay:
        return overlay[rel]
    path = root.joinpath(*rel.split("/"))
    try:
        _refuse(path.is_file(), rule, rel + " is not a file")
        return path.read_bytes()
    except OSError:
        raise Refusal(rule, rel + " cannot be read") from None


def _text(raw: bytes, rule: str, rel: str) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Refusal(rule, rel + " is not UTF-8") from None


def _yaml(raw: bytes, rel: str) -> Any:
    try:
        return safe_load(raw)
    except Exception:  # every YAML parse error, whatever its class, is the catalogue's refusal
        raise Refusal("R2", rel + " does not parse") from None


def _lines(raw: bytes) -> list:
    """The file's lines as bytes, each with its line feed (the last one without, if the file has none)."""
    if not raw:
        return []
    parts = raw.split(b"\n")
    if parts[-1] == b"":
        parts.pop()
        return [p + b"\n" for p in parts]
    return [p + b"\n" for p in parts[:-1]] + [parts[-1]]


def span_bytes(raw: bytes, first: int, last: int) -> bytes:
    """The bytes from the first byte of line `first` to the last byte of line `last`, with that line's line feed."""
    return b"".join(_lines(raw)[first - 1:last])


# ---------------------------------------------------------------- R1 shape

def _str(value: Any) -> bool:
    return type(value) is str and value != ""


def _closed(value: Any, members: tuple) -> bool:
    return type(value) is dict and set(value) == set(members)


def _rel_path(value: Any) -> bool:
    return (_str(value) and REPO_PATH.fullmatch(value) is not None
            and all(part not in (".", "..") for part in value.split("/")))


def _span(value: Any) -> bool:
    if not _closed(value, SPAN_MEMBERS):
        return False
    lines, evidence = value["lines"], value["evidence"]
    return (_rel_path(value["path"]) and type(lines) is list and len(lines) == 2
            and all(type(n) is int for n in lines) and 1 <= lines[0] <= lines[1]
            and type(value["sha256"]) is str and HEX64.fullmatch(value["sha256"]) is not None
            and type(evidence) is list and len(evidence) >= 1 and all(_str(e) for e in evidence)
            and len(set(evidence)) == len(evidence))


def _spans(value: Any) -> bool:
    return type(value) is list and 1 <= len(value) <= 2 and all(_span(s) for s in value)


def _shape(data: Any) -> None:
    rule = "R1"
    _refuse(_closed(data, TOP), rule, "the top level is closed: " + ", ".join(TOP))
    _refuse(data["schemaVersion"] == SCHEMA_VERSION, rule, "schemaVersion is " + SCHEMA_VERSION)
    _refuse(data["adr"] == ADR_PATH, rule, "adr is " + ADR_PATH)
    _refuse(type(data["policySha256"]) is str and HEX64.fullmatch(data["policySha256"]) is not None, rule,
            "policySha256 is a sha256")
    cats = data["catalogues"]
    _refuse(type(cats) is list and all(_closed(c, ("path", "sha256")) and _rel_path(c["path"])
                                       and type(c["sha256"]) is str and HEX64.fullmatch(c["sha256"]) is not None
                                       for c in cats), rule, "catalogues are closed {path, sha256} objects")
    for key in ("repositories", "deployables", "outsideCatalogue", "exceptions"):
        _refuse(type(data[key]) is list, rule, key + " is a list")
    for row in data["repositories"]:
        _refuse(_closed(row, REPOSITORY_MEMBERS), rule, "a repository row is closed: " + ", ".join(REPOSITORY_MEMBERS))
        _refuse(_str(row["id"]) and _str(row["name"]) and _str(row["toolchain"]), rule,
                "a repository row's id, name and toolchain are strings")
        _refuse(type(row["rNumber"]) is str and R_NUMBER.fullmatch(row["rNumber"]) is not None, rule,
                "rNumber is RNN")
        langs = row["languages"]
        _refuse(type(langs) is list and len(langs) >= 1 and all(type(x) is str and x in LANGUAGES for x in langs)
                and len(set(langs)) == len(langs), rule, "languages are distinct members of LANGUAGES")
        _refuse(_spans(row["sources"]), rule, "a repository row has 1 or 2 closed spans")
    for row in data["deployables"]:
        _refuse(_closed(row, DEPLOYABLE_MEMBERS), rule, "a deployable row is closed: " + ", ".join(DEPLOYABLE_MEMBERS))
        _refuse(all(_str(row[k]) for k in ("id", "ownerRepository", "kind", "toolchain")), rule,
                "a deployable row's id, ownerRepository, kind and toolchain are strings")
        for key, values in (("plannedLanguage", LANGUAGES), ("plane", PLANES), ("planeSource", PLANE_SOURCES),
                            ("status", STATUSES)):
            _refuse(type(row[key]) is str and row[key] in values, rule, key + " is one of " + ", ".join(values))
        _refuse(_span(row["source"]), rule, "a deployable row has one closed span")
    for row in data["outsideCatalogue"]:
        _refuse(_closed(row, OUTSIDE_MEMBERS), rule, "an outside row is closed: " + ", ".join(OUTSIDE_MEMBERS))
        _refuse(_str(row["id"]) and _str(row["ownerRepository"]), rule, "an outside row's id and owner are strings")
        _refuse(type(row["plannedLanguage"]) is str and row["plannedLanguage"] in LANGUAGES, rule,
                "plannedLanguage is one of " + ", ".join(LANGUAGES))
        _refuse(_spans(row["sources"]), rule, "an outside row has 1 or 2 closed spans")
    for row in data["exceptions"]:
        _refuse(_closed(row, EXCEPTION_MEMBERS), rule, "an exception row is closed: " + ", ".join(EXCEPTION_MEMBERS))
        _refuse(all(_str(row[k]) for k in ("deployable", "evidence", "reviewTrigger")), rule,
                "an exception row's deployable, evidence and reviewTrigger are strings")
        _refuse(type(row["status"]) is str and row["status"] in STATUSES, rule, "status is one of " + ", ".join(STATUSES))
        for key in ("defaultLanguage", "plannedLanguage"):
            _refuse(type(row[key]) is str and row[key] in LANGUAGES, rule, key + " is one of " + ", ".join(LANGUAGES))
        _refuse(_closed(row["owner"], ("repository", "packet")) and _str(row["owner"]["repository"])
                and _str(row["owner"]["packet"]), rule, "owner is a closed {repository, packet} object")


# ---------------------------------------------------------------- R2 catalogues and policy

def _catalogues(data: dict, root: Path, overlay: dict) -> tuple:
    rule = "R2"
    _refuse([c["path"] for c in data["catalogues"]] == list(CATALOGUES), rule,
            "catalogues are exactly " + " and ".join(CATALOGUES) + ", in that order")
    raws = {}
    for cat in data["catalogues"]:
        raw = _read(root, overlay, cat["path"], rule)
        _refuse(hashlib.sha256(raw).hexdigest() == cat["sha256"], rule, cat["path"] + "'s sha256 is not the head's")
        raws[cat["path"]] = raw
    services = _yaml(raws[SERVICES_PATH], SERVICES_PATH)
    _refuse(type(services) is dict and type(services.get("services")) is list
            and all(type(s) is dict and _str(s.get("id")) for s in services["services"]), rule,
            "services.yaml lists services with ids")
    ids = [s["id"] for s in services["services"]]
    _refuse(len(set(ids)) == len(ids), rule, "services.yaml's ids are unique")
    counts = services.get("counts")
    _refuse(type(counts) is dict and type(counts.get("total")) is int and counts["total"] == len(ids), rule,
            "services.yaml's ids number its counts.total")
    repositories = _yaml(raws[REPOSITORIES_PATH], REPOSITORIES_PATH)
    _refuse(type(repositories) is dict and type(repositories.get("repositories")) is list
            and all(type(r) is dict and _str(r.get("id")) and _str(r.get("name")) for r in repositories["repositories"]),
            rule, "repositories.yaml lists repositories with ids and names")
    repo_ids = [r["id"] for r in repositories["repositories"]]
    _refuse(len(set(repo_ids)) == len(repo_ids), rule, "repositories.yaml's ids are unique")
    _refuse(len(repo_ids) == REPOSITORY_COUNT, rule, "repositories.yaml lists %d repositories" % REPOSITORY_COUNT)
    return services, repositories


def _policy(data: dict, adr: str) -> None:
    rule = "R2"
    _refuse(data["policySha256"] == POLICY_SHA256, rule, "policySha256 is POLICY_SHA256")
    lines = adr.split("\n")
    _refuse(lines.count(POLICY_BEGIN) == 1 and lines.count(POLICY_END) == 1, rule,
            "the ADR has one policy block")
    begin = lines.index(POLICY_BEGIN)
    _refuse(lines.index(POLICY_END) == begin + 2, rule, "the ADR's policy block is one line")
    line = lines[begin + 1]
    _refuse(line.startswith("> "), rule, "the ADR's policy line is '> ' and the text")
    _refuse(hashlib.sha256(line[2:].encode("utf-8")).hexdigest() == POLICY_SHA256, rule,
            "the ADR's policy text is not LANG-D2 (a)")


# ---------------------------------------------------------------- R3 deployables

def _deployables(data: dict, services: dict) -> dict:
    rule = "R3"
    catalogued = {s["id"]: s for s in services["services"]}
    ids = [row["id"] for row in data["deployables"]]
    _refuse(len(set(ids)) == len(ids), rule, "each deployable appears once")
    _refuse(set(ids) == set(catalogued), rule, "the deployables are exactly services.yaml's")
    for row in data["deployables"]:
        entry = catalogued[row["id"]]
        _refuse(row["ownerRepository"] == entry.get("ownerRepository"), rule,
                row["id"] + ": ownerRepository is the catalogue's")
        _refuse(row["kind"] == entry.get("kind"), rule, row["id"] + ": kind is the catalogue's")
        _refuse(row["id"] in EXPECTED, rule, row["id"] + ": no expected placement")
        got = (row["status"], row["plane"], row["planeSource"], row["plannedLanguage"])
        _refuse(got == EXPECTED[row["id"]], rule,
                row["id"] + ": (status, plane, planeSource, plannedLanguage) is %r" % (EXPECTED[row["id"]],))
    return {row["id"]: row for row in data["deployables"]}


# ---------------------------------------------------------------- R4 repositories

def _plan_names(root: Path, overlay: dict) -> set:
    names = {rel[len(PLANS_DIR) + 1:] for rel in overlay if rel.startswith(PLANS_DIR + "/")}
    try:
        names |= set(os.listdir(root.joinpath(*PLANS_DIR.split("/"))))
    except OSError:
        raise Refusal("R4", PLANS_DIR + " cannot be listed") from None
    return {n for n in names if "/" not in n}


def _repositories(data: dict, repositories: dict, root: Path, overlay: dict) -> None:
    rule = "R4"
    pairs = [(row["id"], row["name"]) for row in data["repositories"]]
    catalogued = [(r["id"], r["name"]) for r in repositories["repositories"]]
    _refuse(len(set(pairs)) == len(pairs) and len({p[0] for p in pairs}) == len(pairs), rule,
            "each repository appears once")
    _refuse(set(pairs) == set(catalogued), rule, "the repositories are exactly repositories.yaml's ids and names")
    names = _plan_names(root, overlay)
    for row in data["repositories"]:
        found = [n for n in names if (m := PLAN_NAME.fullmatch(n)) and m.group(2) == row["name"].lower()]
        _refuse(len(found) == 1, rule, row["id"] + ": one plan " + PLANS_DIR + "/NN-<lowercased name>.md")
        plan = PLANS_DIR + "/" + found[0]
        _refuse(row["rNumber"] == "R" + found[0][:2], rule, row["id"] + ": rNumber is R" + found[0][:2])
        _refuse(row["sources"][0]["path"] == plan, rule, row["id"] + ": the first span is in " + plan)
        _refuse(row["id"] in REPO_LANGUAGES and set(row["languages"]) == set(REPO_LANGUAGES[row["id"]]), rule,
                row["id"] + ": languages are " + ", ".join(REPO_LANGUAGES.get(row["id"], ())))


# ---------------------------------------------------------------- R5 sources

def _has_token(evidence: list, language: str) -> bool:
    return any(token in evidence for token in LANG_TOKEN[language])


def id_token(deployable: str) -> str:
    return ALIAS.get(deployable, "`" + deployable + "`")


def locate(raw: bytes, count: int, sha256: str, first: int = 1) -> bytes | None:
    """The block of exactly `count` contiguous whole lines of `raw` (each with its line feed) whose sha256 is `sha256`,
    wherever it lies in the file, or None (design section 11, errata 2). The base position `first` is tried first, then
    every position from the top; equal digests mean equal texts, so any match satisfies the rule."""
    lines = _lines(raw)
    starts = range(len(lines) - count + 1)
    for start in ([first - 1] if 0 <= first - 1 < len(starts) else []) + list(starts):
        chunk = b"".join(lines[start:start + count])
        if hashlib.sha256(chunk).hexdigest() == sha256:
            return chunk
    return None


def _span_text(span: dict, root: Path, overlay: dict, cache: dict) -> str:
    rule = "R5"
    path, (first, last) = span["path"], span["lines"]
    if path not in cache:
        cache[path] = _read(root, overlay, path, rule)
    chunk = locate(cache[path], last - first + 1, span["sha256"], first)
    _refuse(chunk is not None, rule, "%s: no block of %d lines (cited at %d-%d) matches its digest"
            % (path, last - first + 1, first, last))
    text = _text(chunk, rule, path)
    for evidence in span["evidence"]:
        _refuse(evidence in text, rule, "%s:%d-%d does not carry %r" % (path, first, last, evidence))
    return text


def _sources(data: dict, root: Path, overlay: dict) -> int:
    rule = "R5"
    cache: dict = {}
    count = 0
    for row in data["repositories"]:
        texts = [_span_text(s, root, overlay, cache) for s in row["sources"]]
        count += len(texts)
        evidence = [e for s in row["sources"] for e in s["evidence"]]
        for language in row["languages"]:
            _refuse(_has_token(evidence, language), rule, row["id"] + ": its spans do not carry " + language)
        _refuse(any(row["toolchain"] in t for t in texts), rule, row["id"] + ": toolchain is not in its spans")
    for row in data["deployables"]:
        text = _span_text(row["source"], root, overlay, cache)
        count += 1
        evidence = row["source"]["evidence"]
        _refuse(id_token(row["id"]) in evidence, rule, row["id"] + ": evidence lacks " + id_token(row["id"]))
        _refuse(_has_token(evidence, row["plannedLanguage"]), rule,
                row["id"] + ": evidence lacks the token of " + row["plannedLanguage"])
        _refuse(row["toolchain"] in text, rule, row["id"] + ": toolchain is not in its span")
    for row in data["outsideCatalogue"]:
        for span in row["sources"]:
            _span_text(span, root, overlay, cache)
            count += 1
    return count


# ---------------------------------------------------------------- R6 outside the catalogue

def _outside(data: dict) -> None:
    rule = "R6"
    ids = [row["id"] for row in data["outsideCatalogue"]]
    _refuse(len(set(ids)) == len(ids) and set(ids) == set(OUTSIDE_EXPECTED), rule,
            "the outside rows are exactly " + ", ".join(OUTSIDE_EXPECTED))
    for row in data["outsideCatalogue"]:
        _refuse((row["ownerRepository"], row["plannedLanguage"]) == OUTSIDE_EXPECTED[row["id"]], rule,
                row["id"] + ": (ownerRepository, plannedLanguage) is %r" % (OUTSIDE_EXPECTED[row["id"]],))
        evidence = [e for s in row["sources"] for e in s["evidence"]]
        _refuse(_has_token(evidence, row["plannedLanguage"]), rule,
                row["id"] + ": its spans do not carry " + row["plannedLanguage"])


# ---------------------------------------------------------------- R7 exceptions

def _exceptions(data: dict, deployables: dict, services: dict) -> None:
    rule = "R7"
    wanted = [d for d, row in deployables.items() if row["status"] in EXCEPTION_STATUSES]
    named = [row["deployable"] for row in data["exceptions"]]
    _refuse(len(set(named)) == len(named) and set(named) == set(wanted), rule,
            "one exception row per " + " or ".join(EXCEPTION_STATUSES) + " deployable, and none otherwise")
    ownership = services.get("implementationOwnership")
    for row in data["exceptions"]:
        d = deployables[row["deployable"]]
        _refuse(row["status"] == d["status"], rule, row["deployable"] + ": status is the deployable's")
        _refuse(row["owner"]["repository"] == d["ownerRepository"], rule,
                row["deployable"] + ": owner.repository is " + d["ownerRepository"])
        entry = ownership.get(row["deployable"]) if type(ownership) is dict else None
        packet = entry.get("packetId") if type(entry) is dict else None
        _refuse(_str(packet) and row["owner"]["packet"] == packet, rule,
                row["deployable"] + ": owner.packet is services.yaml's implementationOwnership packet")
        _refuse(row["plannedLanguage"] == d["plannedLanguage"], rule,
                row["deployable"] + ": plannedLanguage is the deployable's")
        _refuse(row["defaultLanguage"] == DEFAULT_LANGUAGE, rule, row["deployable"] + ": defaultLanguage is GO")
        _refuse(row["evidence"].startswith(PENDING_PREFIX), rule, row["deployable"] + ": evidence begins PENDING:")
        _refuse(HOTPATH_ITEM in row["evidence"] or row["owner"]["packet"] in row["evidence"], rule,
                row["deployable"] + ": evidence names " + HOTPATH_ITEM + " or the owning packet")


# ---------------------------------------------------------------- R8 the ADR's tables

def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|")


def _where(span: dict) -> str:
    first, last = span["lines"]
    return "`%s:%d`" % (span["path"], first) if first == last else "`%s:%d-%d`" % (span["path"], first, last)


def _row(cells: list) -> str:
    return "| " + " | ".join(_cell(c) for c in cells) + " |"


def render(data: dict, table: str) -> list:
    """The deterministic rendering of one table block, as lines: a caption that pins both catalogues by sha256 (the
    baseline its rows are taken at), a blank line and the table, rows in the data's order."""
    cats = {c["path"]: c["sha256"] for c in data["catalogues"]}
    caption = ("%s, rendered from `%s` by `scripts/language_placement.py`: the baseline at `%s` sha256 `%s` and "
               "`%s` sha256 `%s`." % (TABLE_TITLES[table], DATA_PATH, SERVICES_PATH, cats.get(SERVICES_PATH),
                                      REPOSITORIES_PATH, cats.get(REPOSITORIES_PATH)))
    if table == "repositories":
        head = ["R", "Repository", "Id", "Languages", "Toolchain", "Sources"]
        rows = [[r["rNumber"], "`%s`" % r["name"], "`%s`" % r["id"], ", ".join(r["languages"]), r["toolchain"],
                 "; ".join(_where(s) for s in r["sources"])] for r in data["repositories"]]
    elif table == "deployables":
        head = ["Deployable", "Owner repository", "Kind", "Planned language", "Toolchain", "Plane", "Plane source",
                "Status", "Source"]
        rows = [["`%s`" % r["id"], "`%s`" % r["ownerRepository"], r["kind"], r["plannedLanguage"], r["toolchain"],
                 r["plane"], r["planeSource"], r["status"], _where(r["source"])] for r in data["deployables"]]
    elif table == "outsideCatalogue":
        head = ["Row", "Owner repository", "Planned language", "Sources"]
        rows = [["`%s`" % r["id"], "`%s`" % r["ownerRepository"], r["plannedLanguage"],
                 "; ".join(_where(s) for s in r["sources"])] for r in data["outsideCatalogue"]]
    else:
        head = ["Deployable", "Status", "Default", "Planned", "Owner (repository, packet)", "Evidence",
                "Review trigger"]
        rows = [["`%s`" % r["deployable"], r["status"], r["defaultLanguage"], r["plannedLanguage"],
                 "`%s`, %s" % (r["owner"]["repository"], r["owner"]["packet"]), r["evidence"], r["reviewTrigger"]]
                for r in data["exceptions"]]
    return [caption, "", _row(head), "|" + "---|" * len(head)] + [_row(r) for r in rows]


def _markers(table: str) -> tuple:
    return "<!-- language-placement:%s:begin -->" % table, "<!-- language-placement:%s:end -->" % table


def _tables(data: dict, adr: str) -> None:
    rule = "R8"
    lines = adr.split("\n")
    for table in TABLES:
        begin, end = _markers(table)
        _refuse(lines.count(begin) == 1 and lines.count(end) == 1, rule, "the ADR has one " + table + " block")
        a, b = lines.index(begin), lines.index(end)
        _refuse(a < b and lines[a + 1:b] == render(data, table), rule,
                "the ADR's " + table + " table is not the data's rendering")


# ---------------------------------------------------------------- the check

def check(root: Path = ROOT, overlay: dict | None = None) -> dict:
    """R1 to R8 over the tree at `root`; `overlay` maps repository paths to bytes that stand in for the tree's (for
    in-memory checks). Raises Refusal(rule, message) on the first rule broken; otherwise returns the counts."""
    root = Path(root)
    overlay = dict(overlay or {})
    raw = _read(root, overlay, DATA_PATH, "R1")
    try:
        data = strict(raw)
    except (ValueError, RecursionError) as exc:
        raise Refusal("R1", "%s: %s" % (DATA_PATH, exc if type(exc) is ValueError else type(exc).__name__)) from None
    _shape(data)
    services, repositories = _catalogues(data, root, overlay)
    adr = _text(_read(root, overlay, ADR_PATH, "R2"), "R2", ADR_PATH)
    _policy(data, adr)
    deployables = _deployables(data, services)
    _repositories(data, repositories, root, overlay)
    spans = _sources(data, root, overlay)
    _outside(data)
    _exceptions(data, deployables, services)
    _tables(data, adr)
    by_status = {s: sum(1 for r in data["deployables"] if r["status"] == s) for s in STATUSES}
    by_plane = {p: sum(1 for r in data["deployables"] if r["plane"] == p) for p in PLANES}
    return {"repositories": len(data["repositories"]), "deployables": len(data["deployables"]),
            "byStatus": by_status, "byPlane": by_plane, "outsideCatalogue": len(data["outsideCatalogue"]),
            "exceptions": len(data["exceptions"]), "spans": spans}


USAGE = "usage: language_placement.py check [--root DIR]"


def main(argv: list) -> int:
    if not argv or argv[0] != "check" or len(argv) not in (1, 3) or (len(argv) == 3 and argv[1] != "--root"):
        print(USAGE)
        return 2
    root = Path(argv[2]) if len(argv) == 3 else ROOT
    try:
        summary = check(root)
    except Refusal as exc:
        print("refused: %s" % exc)
        return 1
    print("language placement: accepted; %d repositories, %d deployables (%s; planes %s), %d outside the catalogue, "
          "%d exceptions, %d spans; the policy line and the four tables match"
          % (summary["repositories"], summary["deployables"],
             ", ".join("%s %d" % kv for kv in summary["byStatus"].items()),
             ", ".join("%s %d" % kv for kv in summary["byPlane"].items()),
             summary["outsideCatalogue"], summary["exceptions"], summary["spans"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
