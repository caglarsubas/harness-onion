"""D5a oracle for MET-GOV-004 (LANG-PLACEMENT-ADR-001): the language-placement checker, black-box.

Every expected value here comes from the closed design (revision 4, sha256 169d02bc..., with the errata of its
section 11), its dossier and the owner's LANG-D2. The candidate is reached only through its published command line,
``python3 scripts/language_placement.py check --root <dir>`` (design section 4), run with ``sys.executable``. Its data
file and ADR are read as data at run time; nothing is imported from it.

Each mutation runs on a temporary working copy of the repository root: the plans, ADRs, cited texts, catalogues, data
file, every span path and the files of ``scripts/`` are copied with real copies (``shutil.copy2``), never linked
(errata 3). Every copy lives under one temporary parent made for the session, is removed when its test ends, passed or
failed, and the parent is removed at the end of the session. A mutation test first requires the pristine copy to be
accepted, so that a refusal proves the mutation, not a broken copy.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CHECKER = "scripts/language_placement.py"
SAFE_YAML = "scripts/safe_yaml.py"
DATA = "architecture/language-placement.json"
ADR = "docs/adr/0010-language-placement.md"
SERVICES = "architecture/services.yaml"
REPOSITORIES = "architecture/repositories.yaml"
PLANS = "docs/repositories"
ALPHA2 = "docs/alpha-2"
W01 = ALPHA2 + "/W01_AMENDMENT_W02D.md"
ETP = ALPHA2 + "/ENFORCEMENT_TEST_PLAN.md"
MAP = ALPHA2 + "/HARNESS_PAPER_REPOSITORY_MAP.md"
CITED = (W01, ETP, MAP, ALPHA2 + "/SECCOMP_ALLOWLISTS_V3.md")
TIMEOUT = 120
TEMP_PREFIX = "language-placement-oracle-"
RULES = tuple(f"R{n}" for n in range(1, 9))

# ------------------------------------------------------------------ design sections 3 and 4: the closed constants

SCHEMA_VERSION = "planeon.internal.language-placement/v1"
POLICY_SHA256 = "4b0a8a4b9e043823cfa884bdb883ae5b8f796877ead7bdbc413b318082fbc441"
POLICY_CHARACTERS = 1051
POLICY_BEGIN = "<!-- language-policy:begin -->"
POLICY_END = "<!-- language-policy:end -->"
LANGUAGES = ("PYTHON", "GO", "RUST", "TYPESCRIPT", "UPSTREAM_OWN")
PLANES = ("CONTROL", "DATA", "UNSTATED")
STATUSES = ("AS_PLANNED", "PENDING_HOTPATH_DECISION", "CONTROL_LOOP_TO_BE_CONFIRMED", "NO_STATED_DEFAULT")
PLANE_SOURCES = ("KIND_RULE", "OWNER_LANG_D2", "NOT_STATED")
LANG_TOKEN = {"PYTHON": ("Python",), "GO": ("Go 1.26.7",), "TYPESCRIPT": ("TypeScript",), "RUST": ("Rust",),
              "UPSTREAM_OWN": ("upstream", "OSS implementation")}
ALIAS = {"operator": "`mas-harness-operator`", "otel-collector": "OTel Collector"}
HOTPATH = "LANG-HOTPATH-DECISION-001"
PENDING_PREFIX = "PENDING:"
# Design section 11, errata 2: the ADR's sentence beside the tables.
SPAN_SENTENCE = ("Each cited span is located by its content: a shift of the cited lines is accepted, and any change to "
                 "their text is refused.")

MEMBERS = {
    "top": {"schemaVersion", "adr", "policySha256", "catalogues", "repositories", "deployables", "outsideCatalogue",
            "exceptions"},
    "catalogue": {"path", "sha256"},
    "repository": {"id", "name", "rNumber", "languages", "toolchain", "sources"},
    "span": {"path", "lines", "sha256", "evidence"},
    "deployable": {"id", "ownerRepository", "kind", "plannedLanguage", "toolchain", "plane", "planeSource", "status",
                   "source"},
    "outside": {"id", "ownerRepository", "plannedLanguage", "sources"},
    "exception": {"deployable", "status", "defaultLanguage", "plannedLanguage", "owner", "evidence", "reviewTrigger"},
    "owner": {"repository", "packet"},
}

# ------------------------------------------------------------------ design section 5.2: status and planned language

AS_PLANNED = {
    "operator": "GO", "fleet-sync-agent": "GO", "bundle-verifier": "GO", "control-web": "TYPESCRIPT",
    "inference-api": "PYTHON", "index-worker": "PYTHON", "evidence-service": "PYTHON", "assurance-worker": "PYTHON",
    "orchestration-api": "PYTHON", "orchestration-worker": "PYTHON", "decision-service": "PYTHON",
    "memory-service": "PYTHON", "retrieval-service": "PYTHON", "guardrail-service": "PYTHON",
    "otel-collector": "UPSTREAM_OWN",
}
PENDING_HOTPATH = ("ai-gateway", "experience-gateway", "protocol-gateway", "tool-broker")
CONTROL_LOOP = ("connector-controller",)
NO_STATED_DEFAULT = ("ingest-worker", "domain-service", "policy-decision", "usage-ledger", "registry-service",
                     "governance-service", "sandbox-runner", "profile-compiler-worker")

# ------------------------------------------------------------------ design section 5.1: the plane and its source

CONTROL = {"operator": "OWNER_LANG_D2", "fleet-sync-agent": "KIND_RULE"}
DATA_PLANE = ("ai-gateway", "experience-gateway", "protocol-gateway")
UNSTATED = ("bundle-verifier", "sandbox-runner", "otel-collector", "connector-controller", "control-web",
            "profile-compiler-worker", "ingest-worker", "index-worker", "orchestration-worker", "assurance-worker",
            "policy-decision", "guardrail-service", "usage-ledger", "governance-service", "registry-service",
            "evidence-service", "domain-service", "memory-service", "retrieval-service", "inference-api",
            "orchestration-api", "decision-service", "tool-broker")


def _expected() -> dict:
    status = {i: ("AS_PLANNED", lang) for i, lang in AS_PLANNED.items()}
    status.update({i: ("PENDING_HOTPATH_DECISION", "PYTHON") for i in PENDING_HOTPATH})
    status.update({i: ("CONTROL_LOOP_TO_BE_CONFIRMED", "PYTHON") for i in CONTROL_LOOP})
    status.update({i: ("NO_STATED_DEFAULT", "PYTHON") for i in NO_STATED_DEFAULT})
    plane = {i: ("CONTROL", source) for i, source in CONTROL.items()}
    plane.update({i: ("DATA", "KIND_RULE") for i in DATA_PLANE})
    plane.update({i: ("UNSTATED", "NOT_STATED") for i in UNSTATED})
    assert set(status) == set(plane), "oracle constants: status and plane rows differ"
    return {i: (status[i][0], plane[i][0], plane[i][1], status[i][1]) for i in sorted(status)}


EXPECTED = _expected()  # id -> (status, plane, planeSource, plannedLanguage)

# The design's own arithmetic (sections 5.1 and 5.2): checked at import, so a slip in these constants stops the module.
assert (len(AS_PLANNED), len(PENDING_HOTPATH), len(CONTROL_LOOP), len(NO_STATED_DEFAULT)) == (15, 4, 1, 8)
assert (len(CONTROL), len(DATA_PLANE), len(UNSTATED)) == (2, 3, 23)
assert len(EXPECTED) == 28 and len(set(UNSTATED)) == 23

# ------------------------------------------------------------------ design section 5.4: the exceptions

EXCEPTIONS = {
    "ai-gateway": ("mas-harness-runtime-plane", "RUN-001"),
    "experience-gateway": ("mas-harness-runtime-plane", "RUN-EXP-001"),
    "protocol-gateway": ("mas-harness-execution-plane", "EXEC-PROT-001"),
    "tool-broker": ("mas-harness-execution-plane", "EXEC-TOOL-001"),
    "connector-controller": ("mas-harness-knowledge-plane", "KN-DATA-001"),
}

# ------------------------------------------------------------------ the repositories (design 3, 5.3; dossier 4)

R_NUMBER = {
    "Harness-Engineering": "R00", "mas-harness-contracts": "R01", "mas-harness-sdks": "R02",
    "mas-harness-industry-packs": "R03", "mas-harness-control-plane": "R04", "mas-harness-runtime-plane": "R05",
    "mas-harness-model-plane": "R06", "mas-harness-knowledge-plane": "R07", "mas-harness-execution-plane": "R08",
    "mas-harness-trust-plane": "R09", "mas-harness-operator": "R10", "mas-harness-distribution": "R11",
    "mas-harness-conformance-labs": "R12",
}
LANGUAGES_STATED = {
    "mas-harness-sdks": {"PYTHON", "TYPESCRIPT"},
    "mas-harness-operator": {"GO", "RUST"},
    "mas-harness-conformance-labs": {"PYTHON", "RUST"},
}
TWO_SPANS = {"mas-harness-operator", "mas-harness-conformance-labs"}


def _plan(name: str) -> str:
    return f"{PLANS}/{R_NUMBER[name][1:]}-{name.lower()}.md"


P04, P05, P06 = _plan("mas-harness-control-plane"), _plan("mas-harness-runtime-plane"), _plan("mas-harness-model-plane")
P07, P08, P09 = (_plan("mas-harness-knowledge-plane"), _plan("mas-harness-execution-plane"),
                 _plan("mas-harness-trust-plane"))
P02, P10, P12 = _plan("mas-harness-sdks"), _plan("mas-harness-operator"), _plan("mas-harness-conformance-labs")

# ------------------------------------------------------------------ design section 5.3: the spans at the base

DEPLOYABLE_SPANS = {"operator": (P10, 152, 153), "bundle-verifier": (P10, 152, 154),
                    "fleet-sync-agent": (P10, 152, 155), "otel-collector": (P09, 100, 100),
                    "inference-api": (P06, 99, 99), "ai-gateway": (P05, 88, 88),
                    "experience-gateway": (P05, 88, 89), "control-web": (P04, 102, 102),
                    "profile-compiler-worker": (P04, 103, 103)}
for _i in ("policy-decision", "guardrail-service", "governance-service", "registry-service", "evidence-service",
           "assurance-worker", "usage-ledger"):
    DEPLOYABLE_SPANS[_i] = (P09, 90, 100)
for _i in ("protocol-gateway", "orchestration-api", "orchestration-worker", "tool-broker", "sandbox-runner",
           "decision-service"):
    DEPLOYABLE_SPANS[_i] = (P08, 101, 102)
for _i in ("domain-service", "connector-controller", "ingest-worker", "retrieval-service", "index-worker",
           "memory-service"):
    DEPLOYABLE_SPANS[_i] = (P07, 117, 118)
assert set(DEPLOYABLE_SPANS) == set(EXPECTED)

REPOSITORY_SPANS = {
    "mas-harness-operator": [(P10, 152, 152), (W01, 24, 24)],
    "mas-harness-conformance-labs": [(P12, 408, 409), (ETP, 12, 13)],
    "mas-harness-sdks": [(P02, 92, 94)],
    "mas-harness-control-plane": [(P04, 102, 103)],
    "mas-harness-runtime-plane": [(P05, 88, 93)],
}
OUTSIDE = {  # id -> (owner's rNumber, plannedLanguage, spans)
    "reference-channel-ui": ("R05", "TYPESCRIPT", [(P05, 90, 93)]),
    "model-backends": ("R06", "UPSTREAM_OWN", [(P06, 100, 100), (MAP, 32, 35)]),
    "native-host-enforcement-roles": ("R10", "RUST", [(W01, 24, 24)]),
    "r12-native-probes": ("R12", "RUST", [(ETP, 12, 13)]),
    "typescript-sdk": ("R02", "TYPESCRIPT", [(P02, 94, 94)]),
}


# ------------------------------------------------------------------ helpers

def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _scrub(text: str, *roots: Path) -> str:
    """Replace the working roots in the checker's output, so no temporary or local path is reported."""
    names = set()
    for root in (*roots, ROOT):
        names.add(str(root))
        names.add(os.path.realpath(root))
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<root>")
    return re.sub(r"pytest-of-[^/\s'\"]+", "pytest-of-<x>", text)


def _tail(text: str) -> str:
    return text[-1500:]


def _run(root: Path, args) -> tuple:
    if not (root / CHECKER).is_file():
        pytest.fail(f"the checker {CHECKER} is absent")
    try:
        proc = subprocess.run([sys.executable, "-B", CHECKER, *args], cwd=str(root), stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        pytest.fail(f"the checker did not finish within {TIMEOUT} s")
    out = (proc.stdout + proc.stderr).decode("utf-8", "replace")
    return int(proc.returncode), _scrub(out, root)


def _check(root: Path) -> tuple:
    return _run(root, ["check", "--root", str(root)])


def _has_rule(out: str, rule: str) -> bool:
    return re.search(rf"(?<![A-Za-z0-9]){rule}(?![0-9])", out) is not None


def _new_rule_lines(out: str, pristine_out: str, rule: str) -> list:
    """Output lines naming the rule that the pristine run did not print."""
    seen = set(pristine_out.splitlines())
    return [line for line in out.splitlines() if _has_rule(line, rule) and line not in seen]


def _read(root: Path, rel: str) -> bytes:
    path = root / rel
    if not path.is_file():
        pytest.fail(f"{rel} is absent")
    return path.read_bytes()


def _strict(raw: bytes):
    """The design's parse rules (section 4, LAB-RUNPLAN-001's strict()), for the oracle's own reading of the data."""
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate key " + key)
            value[key] = item
        return value

    def constant(name):
        raise ValueError("non-finite number " + name)

    def number(text):
        value = float(text)
        if not math.isfinite(value) or value.is_integer():
            raise ValueError("non-finite or integral float " + text)
        return value

    def integer(text):
        if len(text.lstrip("-")) > 13 or abs(int(text)) > 10 ** 12:
            raise ValueError("integer out of range")
        return int(text)

    if raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("byte-order mark")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant, parse_float=number,
                       parse_int=integer)
    json.dumps(value, ensure_ascii=False).encode("utf-8")
    return value


def _data(root: Path = ROOT):
    raw = _read(root, DATA)
    try:
        return _strict(raw)
    except (ValueError, UnicodeError) as error:
        pytest.fail(f"{DATA} does not parse under the design's rules: {error}")


def _rows(doc, key: str) -> list:
    rows = doc.get(key) if isinstance(doc, dict) else None
    if not isinstance(rows, list):
        pytest.fail(f"the data has no list {key!r}")
    return rows


def _row(rows: list, key: str, value):
    hits = [r for r in rows if isinstance(r, dict) and r.get(key) == value]
    if len(hits) != 1:
        pytest.fail(f"ORACLE-SETUP: expected one row with {key} = {value!r}, found {len(hits)}")
    return hits[0]


def _dep(doc, ident):
    return _row(_rows(doc, "deployables"), "id", ident)


def _repo(doc, name):
    return _row(_rows(doc, "repositories"), "name", name)


def _out(doc, ident):
    return _row(_rows(doc, "outsideCatalogue"), "id", ident)


def _exc(doc, ident):
    return _row(_rows(doc, "exceptions"), "deployable", ident)


def _text_lines(text: str) -> list:
    """Lines split at line feeds only, each with its line feed."""
    return re.findall(r"[^\n]*\n|[^\n]+$", text)


def _lines(raw: bytes) -> list:
    """Lines with their line feeds."""
    out, start = [], 0
    while start < len(raw):
        end = raw.find(b"\n", start)
        if end < 0:
            out.append(raw[start:])
            break
        out.append(raw[start:end + 1])
        start = end + 1
    return out


def _span_count(span) -> int | None:
    lines = span.get("lines") if isinstance(span, dict) else None
    if not (isinstance(lines, list) and len(lines) == 2 and all(type(n) is int for n in lines)):
        return None
    count = lines[1] - lines[0] + 1
    return count if count >= 1 else None


def _locate(raw: bytes, span):
    """Design section 11, errata 2: the 0-based start of a block of exactly last - first + 1 whole lines, anywhere in
    the file, whose sha256 is the span's pin; None when there is none."""
    count = _span_count(span)
    if count is None:
        return None
    parts = _lines(raw)
    for start in range(0, len(parts) - count + 1):
        block = parts[start:start + count]
        if block[-1].endswith(b"\n") and _sha256(b"".join(block)) == span.get("sha256"):
            return start
    return None


def _safe_rel(rel) -> bool:
    return isinstance(rel, str) and rel != "" and not rel.startswith("/") and ".." not in rel.split("/")


def _all_spans(doc) -> list:
    spans = []
    for row in doc.get("deployables", []) if isinstance(doc, dict) else []:
        if isinstance(row, dict) and isinstance(row.get("source"), dict):
            spans.append(row["source"])
    for key in ("repositories", "outsideCatalogue"):
        for row in doc.get(key, []) if isinstance(doc, dict) else []:
            if isinstance(row, dict) and isinstance(row.get("sources"), list):
                spans.extend(s for s in row["sources"] if isinstance(s, dict))
    return spans


def _span_paths() -> set:
    try:
        doc = json.loads((ROOT / DATA).read_bytes().decode("utf-8"))
    except (OSError, ValueError):
        return set()
    paths = {s.get("path") for s in _all_spans(doc)}
    for entry in doc.get("catalogues", []) if isinstance(doc, dict) else []:
        if isinstance(entry, dict):
            paths.add(entry.get("path"))
    if isinstance(doc, dict):
        paths.add(doc.get("adr"))
    return {p for p in paths if _safe_rel(p)}


def _make_copy(dst: Path, scripts=None) -> Path:
    """A working copy of the root, by real copies only (shutil.copy2): the files of scripts/ and everything the design
    names. Nothing is linked into the subject tree (design section 11, errata 3)."""
    dst.mkdir(parents=True)
    rels = {SERVICES, REPOSITORIES, DATA, ADR, *CITED, *_span_paths()}
    if scripts is None:
        rels.update(f"scripts/{n}" for n in os.listdir(ROOT / "scripts")
                    if (ROOT / "scripts" / n).is_file() and not n.endswith(".pyc"))
    else:
        rels.update(scripts)
    for directory in (PLANS, "docs/adr"):
        if (ROOT / directory).is_dir():
            rels.update(f"{directory}/{n}" for n in os.listdir(ROOT / directory) if (ROOT / directory / n).is_file())
    for rel in sorted(rels):
        src = ROOT / rel
        if src.is_file():
            (dst / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst / rel)
    return dst


def _remove(path: Path) -> None:
    """Remove a working tree whole, read-only copies included."""
    if not os.path.lexists(path):
        return
    os.chmod(path, 0o700)
    for top, dirs, _ in os.walk(path):
        for name in dirs:
            os.chmod(os.path.join(top, name), 0o700)
    shutil.rmtree(path)


@contextlib.contextmanager
def _copy_of_root(parent: Path, scripts=None):
    """A working copy under the session's temporary parent, removed when the block ends, however it ends."""
    holder = Path(tempfile.mkdtemp(prefix="copy-", dir=parent))
    try:
        yield _make_copy(holder / "root", scripts=scripts)
    finally:
        _remove(holder)


_STYLES = [(indent, compact, ascii_, sort, tail) for indent in (2, 4, 1, None) for compact in (False, True)
           for ascii_ in (False, True) for sort in (False, True) for tail in ("\n", "")]


def _render(value, style) -> bytes:
    indent, compact, ascii_, sort, tail = style
    separators = (",", ":") if compact else ((",", ": ") if indent is not None else (", ", ": "))
    text = json.dumps(value, indent=indent, ensure_ascii=ascii_, sort_keys=sort, separators=separators)
    return (text + tail).encode("utf-8")


def _dump(doc, like: bytes) -> bytes:
    """Serialize in the data file's own layout where one of the common layouts reproduces it exactly."""
    try:
        original = json.loads(like.decode("utf-8"))
    except ValueError:
        return _render(doc, _STYLES[0])
    for style in _STYLES:
        if _render(original, style) == like:
            return _render(doc, style)
    return _render(doc, _STYLES[0])


def _flip_hex(value: str) -> str:
    return value[:-1] + ("0" if value[-1:] != "0" else "1")


def _change_letter(line: str) -> str:
    body = line.rstrip("\n")
    tail = line[len(body):]
    for pos in range(2, len(body)):
        if body[pos].isascii() and body[pos].isalpha():
            return body[:pos] + ("x" if body[pos] != "x" else "y") + body[pos + 1:] + tail
    pytest.fail("ORACLE-SETUP: no letter to change in the row")


def _change_one_byte(line: bytes) -> bytes:
    """One character changed: the line's first ASCII letter."""
    for pos, byte in enumerate(line):
        if 65 <= byte <= 90 or 97 <= byte <= 122:
            return line[:pos] + (b"x" if byte != ord("x") else b"y") + line[pos + 1:]
    pytest.fail("ORACLE-SETUP: no letter to change in the cited line")


_BEGIN = re.compile(r"^<!-- language-placement:([A-Za-z0-9_.-]+):begin -->$")


def _blocks(lines: list) -> list:
    """(name, begin index, end index or None) for each table block of the ADR, in order."""
    blocks = []
    for i, line in enumerate(lines):
        match = _BEGIN.match(line.rstrip("\n"))
        if match:
            end = f"<!-- language-placement:{match.group(1)}:end -->"
            j = next((k for k in range(i + 1, len(lines)) if lines[k].rstrip("\n") == end), None)
            blocks.append((match.group(1), i, j))
    return blocks


def _table_rows(lines: list, begin: int, end: int) -> list:
    rows = [k for k in range(begin + 1, end) if lines[k].startswith("|")]
    return [k for k in rows if not re.fullmatch(r"\|[\s:|-]*\|?\n?", lines[k])]


def _policy_index(lines: list) -> int:
    begin = [i for i, line in enumerate(lines) if line.rstrip("\n") == POLICY_BEGIN]
    end = [i for i, line in enumerate(lines) if line.rstrip("\n") == POLICY_END]
    if not (len(begin) == 1 and len(end) == 1 and end[0] == begin[0] + 2):
        pytest.fail("the ADR's policy block is not one line between one begin and one end marker")
    return begin[0] + 1


def _services(text: str) -> tuple:
    """A line scan of services.yaml's own layout (standard library only): id -> {ownerRepository, kind}, the
    implementationOwnership packets, and counts.total."""
    services, packets, total = {}, {}, None
    order = []
    section, current = None, None
    for line in text.splitlines():
        if line and not line.startswith((" ", "#")):
            section, current = line.split(":", 1)[0], None
            continue
        if section == "counts":
            match = re.match(r"^  total: (\d+)$", line)
            if match:
                total = int(match.group(1))
        elif section == "implementationOwnership":
            match = re.match(r"^  ([a-z0-9-]+): \{packetId: ([A-Z0-9-]+),", line)
            if match:
                packets[match.group(1)] = match.group(2)
        elif section == "services":
            match = re.match(r"^  - id: ([a-z0-9-]+)$", line)
            if match:
                current = match.group(1)
                order.append(current)
                services.setdefault(current, {})
                continue
            match = re.match(r"^    (ownerRepository|kind): (\S+)$", line)
            if match and current:
                services[current][match.group(1)] = match.group(2)
    return order, services, packets, total


def _repositories(text: str) -> list:
    """A line scan of repositories.yaml's own layout: [(id, name)] in order."""
    out, section, current = [], None, None
    for line in text.splitlines():
        if line and not line.startswith((" ", "#")):
            section = line.split(":", 1)[0]
            continue
        if section != "repositories":
            continue
        match = re.match(r"^  - id: (\S+)$", line)
        if match:
            current = match.group(1)
            continue
        match = re.match(r"^    name: (\S+)$", line)
        if match and current:
            out.append((current, match.group(1)))
            current = None
    return out


def _id_token(ident: str) -> str:
    return ALIAS.get(ident, f"`{ident}`")


class Copy:
    """A working copy of the root that the oracle mutates."""

    def __init__(self, root: Path):
        self.root = root

    def read(self, rel: str) -> bytes:
        return _read(self.root, rel)

    def write(self, rel: str, raw: bytes, allow_same: bool = False) -> None:
        path = self.root / rel
        if not allow_same and path.is_file() and path.read_bytes() == raw:
            pytest.fail(f"ORACLE-SETUP: the mutation of {rel} changed nothing")
        fresh = path.with_name(path.name + ".oracle-new")
        fresh.write_bytes(raw)
        os.replace(fresh, path)

    def replace(self, rel: str, old: bytes, new: bytes) -> None:
        raw = self.read(rel)
        if old not in raw:
            pytest.fail(f"ORACLE-SETUP: {rel} does not hold the text to change")
        self.write(rel, raw.replace(old, new, 1))

    def doc(self):
        return json.loads(self.read(DATA).decode("utf-8"))

    def put(self, doc) -> None:
        self.write(DATA, _dump(doc, self.read(DATA)))

    def repin(self, rel: str) -> None:
        doc = self.doc()
        _row(_rows(doc, "catalogues"), "path", rel)["sha256"] = _sha256(self.read(rel))
        self.put(doc)

    def check(self) -> tuple:
        return _check(self.root)


@pytest.fixture(scope="session")
def oracle_parent():
    """One temporary parent for the session's copies; it must be empty at the end, and is then removed."""
    parent = Path(tempfile.mkdtemp(prefix=TEMP_PREFIX))
    try:
        yield parent
    finally:
        left = len(os.listdir(parent)) if parent.is_dir() else 0
        _remove(parent)
        assert left == 0, f"{left} working copies were left in the oracle's temporary parent"
        assert not os.path.lexists(parent), "the oracle's temporary parent was not removed"


@pytest.fixture(scope="session")
def oracle_pristine(oracle_parent):
    with _copy_of_root(oracle_parent) as root:
        return _check(root)


@pytest.fixture
def oracle_copy(oracle_parent, oracle_pristine):
    rc, out = oracle_pristine
    assert rc == 0, f"ORACLE-GUARD: the pristine copy is refused (exit {rc}); a mutation proves nothing:\n{_tail(out)}"
    with _copy_of_root(oracle_parent) as root:
        yield Copy(root)


def _refused(work: Copy, rule: str) -> None:
    rc, out = work.check()
    assert rc == 1, f"expected exit 1 naming {rule}; got exit {rc}:\n{_tail(out)}"
    assert "Traceback (most recent call last)" not in out, f"exit 1 by a crash, not a refusal:\n{_tail(out)}"
    assert _has_rule(out, rule), f"exit 1, but {rule} is not in the output:\n{_tail(out)}"


# ------------------------------------------------------------------ the copies themselves (design section 11, errata 3)

def test_copy_shares_no_inode(oracle_parent):
    """No copied file shares an inode with its source, each copy has one link, and copying adds no link to a source."""
    sources = sorted(p for p in (ROOT / "scripts").iterdir() if p.is_file())
    before = {p.name: os.stat(p).st_nlink for p in sources}
    checked = 0
    with _copy_of_root(oracle_parent) as root:
        for top, _, files in os.walk(root):
            for name in files:
                copied = Path(top) / name
                rel = copied.relative_to(root)
                assert not copied.is_symlink(), f"{rel} is a symbolic link"
                mine, theirs = os.stat(copied), os.stat(ROOT / rel)
                assert (mine.st_dev, mine.st_ino) != (theirs.st_dev, theirs.st_ino), f"{rel} shares an inode"
                assert mine.st_nlink == 1, f"{rel}: st_nlink {mine.st_nlink}"
                checked += 1
    after = {p.name: os.stat(p).st_nlink for p in sources}
    assert checked > 0 and before == after, "copying changed a source's link count"


# ------------------------------------------------------------------ positives and usage (design section 4)

def test_positive_pristine_copy(oracle_pristine):
    rc, out = oracle_pristine
    assert rc == 0, f"check on a pristine copy of the root: exit {rc}:\n{_tail(out)}"


def test_positive_in_place():
    rc, out = _check(ROOT)
    assert rc == 0, f"check --root on the repository root: exit {rc}:\n{_tail(out)}"


def test_positive_default_root():
    rc, out = _run(ROOT, ["check"])
    assert rc == 0, f"check without --root, from the repository root: exit {rc}:\n{_tail(out)}"


def test_positive_dependencies_are_stdlib_and_safe_yaml(oracle_parent):
    """Design section 4: the checker's dependencies are the standard library and scripts/safe_yaml.py."""
    with _copy_of_root(oracle_parent, scripts=(CHECKER, SAFE_YAML)) as root:
        rc, out = _check(root)
    assert rc == 0, f"check with only the checker and safe_yaml.py under scripts/: exit {rc}:\n{_tail(out)}"


def test_control_reserialized_data_accepted(oracle_copy):
    """The oracle's own serializer: the unchanged data, written back, is still accepted."""
    oracle_copy.write(DATA, _dump(oracle_copy.doc(), oracle_copy.read(DATA)), allow_same=True)
    rc, out = oracle_copy.check()
    assert rc == 0, f"the re-serialized unchanged data is refused: exit {rc}:\n{_tail(out)}"


@pytest.mark.parametrize("args", [[], ["verify"], ["check", "--oracle-unknown-option"]],
                         ids=["no-command", "unknown-command", "unknown-option"])
def test_usage_exits_2(args):
    rc, out = _run(ROOT, args)
    assert rc == 2, f"usage error {args!r}: expected exit 2, got {rc}:\n{_tail(out)}"


# ------------------------------------------------------------------ the design's fixed facts, against the data

def test_fixed_data_shape():
    doc = _data()
    assert isinstance(doc, dict) and set(doc) == MEMBERS["top"], f"top-level members {sorted(doc)}"
    assert doc["schemaVersion"] == SCHEMA_VERSION
    assert doc["adr"] == ADR
    assert doc["policySha256"] == POLICY_SHA256
    catalogues = doc["catalogues"]
    assert [c.get("path") for c in catalogues] == [SERVICES, REPOSITORIES], "catalogue paths"
    for entry in catalogues:
        assert set(entry) == MEMBERS["catalogue"]
        assert entry["sha256"] == _sha256(_read(ROOT, entry["path"])), f"{entry['path']} pin"
    for row in doc["repositories"]:
        assert set(row) == MEMBERS["repository"], f"repository members {sorted(row)}"
        assert all(lang in LANGUAGES for lang in row["languages"]), f"{row['name']} languages"
        for span in row["sources"]:
            assert set(span) == MEMBERS["span"]
    for row in doc["deployables"]:
        assert set(row) == MEMBERS["deployable"], f"deployable members {sorted(row)}"
        assert row["plannedLanguage"] in LANGUAGES and row["plane"] in PLANES
        assert row["status"] in STATUSES and row["planeSource"] in PLANE_SOURCES
        assert isinstance(row["source"], dict) and set(row["source"]) == MEMBERS["span"], f"{row['id']}: one span"
    for row in doc["outsideCatalogue"]:
        assert set(row) == MEMBERS["outside"], f"outside members {sorted(row)}"
        assert 1 <= len(row["sources"]) <= 2 and all(set(s) == MEMBERS["span"] for s in row["sources"])
    for row in doc["exceptions"]:
        assert set(row) == MEMBERS["exception"], f"exception members {sorted(row)}"
        assert set(row["owner"]) == MEMBERS["owner"]


def test_fixed_counts():
    doc = _data()
    deployables, repositories = doc["deployables"], doc["repositories"]
    assert len(deployables) == 28 and len(repositories) == 13
    statuses = [row["status"] for row in deployables]
    assert [statuses.count(s) for s in STATUSES] == [15, 4, 1, 8], "AS_PLANNED, PENDING, CONTROL_LOOP, NO_DEFAULT"
    planes = [row["plane"] for row in deployables]
    assert [planes.count(p) for p in PLANES] == [2, 3, 23], "CONTROL, DATA, UNSTATED"


def test_fixed_deployables_match_design_and_catalogue():
    order, services, _, total = _services(_read(ROOT, SERVICES).decode("utf-8"))
    assert total == 28 and len(order) == 28 and set(order) == set(EXPECTED), "the catalogue's 28 ids"
    doc = _data()
    ids = [row["id"] for row in doc["deployables"]]
    assert sorted(ids) == sorted(EXPECTED), "deployable ids"
    for row in doc["deployables"]:
        ident = row["id"]
        got = (row["status"], row["plane"], row["planeSource"], row["plannedLanguage"])
        assert got == EXPECTED[ident], f"{ident}: {got} against the design's {EXPECTED[ident]}"
        assert row["ownerRepository"] == services[ident]["ownerRepository"], f"{ident} ownerRepository"
        assert row["kind"] == services[ident]["kind"], f"{ident} kind"


def test_fixed_policy_line():
    lines = _text_lines(_read(ROOT, ADR).decode("utf-8"))
    assert lines and lines[0].rstrip("\n") == "# ADR 0010: Language placement", "the ADR's title line"
    line = lines[_policy_index(lines)].rstrip("\n")
    assert line.startswith("> "), "the policy line is '> ' + the text"
    text = line[2:]
    assert len(text) == POLICY_CHARACTERS, f"policy text: {len(text)} characters"
    assert _sha256(text.encode("utf-8")) == POLICY_SHA256, "policy text digest"


def test_fixed_exceptions():
    _, services, packets, _ = _services(_read(ROOT, SERVICES).decode("utf-8"))
    doc = _data()
    rows = doc["exceptions"]
    assert sorted(r["deployable"] for r in rows) == sorted(EXCEPTIONS), "one exception row per pending deployable"
    for ident, (repository, packet) in EXCEPTIONS.items():
        row = _exc(doc, ident)
        assert row["owner"] == {"repository": repository, "packet": packet}, f"{ident} owner"
        assert packets[ident] == packet and services[ident]["ownerRepository"] == repository, f"{ident} catalogue"
        assert row["status"] == EXPECTED[ident][0], f"{ident} status"
        assert row["defaultLanguage"] == "GO" and row["plannedLanguage"] == "PYTHON", f"{ident} languages"
        assert row["evidence"].startswith(PENDING_PREFIX), f"{ident} evidence begins {PENDING_PREFIX}"
        assert HOTPATH in row["evidence"], f"{ident} evidence names {HOTPATH}"
        assert ident in row["reviewTrigger"] and HOTPATH in row["reviewTrigger"], f"{ident} review trigger"
    assert "KN-DATA-001" in _exc(doc, "connector-controller")["evidence"]


def test_fixed_repositories():
    doc = _data()
    catalogue = _repositories(_read(ROOT, REPOSITORIES).decode("utf-8"))
    assert len(catalogue) == 13 and {n for _, n in catalogue} == set(R_NUMBER), "the catalogue's 13 repositories"
    rows = doc["repositories"]
    assert sorted((r["id"], r["name"]) for r in rows) == sorted(catalogue), "repository ids and names"
    for row in rows:
        name = row["name"]
        plan = _plan(name)
        assert row["rNumber"] == R_NUMBER[name], f"{name} rNumber"
        assert (ROOT / plan).is_file(), f"{name}: plan {plan}"
        assert row["sources"][0]["path"] == plan, f"{name}: the first span is the plan"
        assert len(row["sources"]) == (2 if name in TWO_SPANS else 1), f"{name}: span count"
        assert len(set(row["languages"])) == len(row["languages"]), f"{name}: languages repeat"
        if name in LANGUAGES_STATED:
            assert set(row["languages"]) == LANGUAGES_STATED[name], f"{name} languages"


def test_fixed_outside_catalogue():
    doc = _data()
    by_number = {r["rNumber"]: r for r in doc["repositories"]}
    rows = doc["outsideCatalogue"]
    assert sorted(r["id"] for r in rows) == sorted(OUTSIDE), "the closed outside id set"
    for ident, (number, language, spans) in OUTSIDE.items():
        row = _out(doc, ident)
        owner = by_number[number]
        assert row["ownerRepository"] in (owner["name"], owner["id"]), f"{ident} owner"
        assert row["plannedLanguage"] == language, f"{ident} language"
        got = sorted((s["path"], s["lines"][0], s["lines"][1]) for s in row["sources"])
        assert got == sorted(spans), f"{ident} spans {got}"


def test_fixed_design_spans():
    doc = _data()
    for ident, (path, first, last) in DEPLOYABLE_SPANS.items():
        source = _dep(doc, ident)["source"]
        assert (source["path"], source["lines"]) == (path, [first, last]), f"{ident} span"
    for name, spans in REPOSITORY_SPANS.items():
        got = [(s["path"], s["lines"][0], s["lines"][1]) for s in _repo(doc, name)["sources"]]
        assert got == spans, f"{name} spans {got}"


def test_fixed_spans_verified_independently():
    """Each span located by content (errata 2), then its evidence, tokens and toolchain checked in the located text."""
    doc = _data()

    def verify(where: str, span: dict) -> str:
        path = span["path"]
        assert _safe_rel(path) and (ROOT / path).is_file(), f"{where}: {path} exists"
        raw = (ROOT / path).read_bytes()
        start = _locate(raw, span)
        assert start is not None, f"{where}: no block of the span's line count has its digest"
        text = b"".join(_lines(raw)[start:start + _span_count(span)]).decode("utf-8")
        for evidence in span["evidence"]:
            assert evidence in text, f"{where}: evidence {evidence!r} occurs in the located span"
        return text

    for row in doc["deployables"]:
        ident = row["id"]
        text = verify(ident, row["source"])
        evidence = row["source"]["evidence"]
        assert _id_token(ident) in evidence, f"{ident}: the id token in the evidence"
        assert any(t in evidence for t in LANG_TOKEN[row["plannedLanguage"]]), f"{ident}: the language token"
        assert row["toolchain"] in text, f"{ident}: toolchain verbatim in the span"
    for row in doc["repositories"]:
        texts = [verify(row["name"], s) for s in row["sources"]]
        for lang in row["languages"]:
            assert any(t in x for t in LANG_TOKEN[lang] for x in texts), f"{row['name']}: {lang} token in a span"
        assert any(row["toolchain"] in x for x in texts), f"{row['name']}: toolchain verbatim in a span"
    for row in doc["outsideCatalogue"]:
        texts = [verify(row["id"], s) for s in row["sources"]]
        assert any(t in x for t in LANG_TOKEN[row["plannedLanguage"]] for x in texts), f"{row['id']}: language token"


def test_fixed_adr_tables():
    lines = _text_lines(_read(ROOT, ADR).decode("utf-8"))
    blocks = _blocks(lines)
    assert len(blocks) == 4, f"four table blocks, found {len(blocks)}"
    assert len({name for name, _, _ in blocks}) == 4, "the table names are distinct"
    services_sha = _sha256(_read(ROOT, SERVICES))
    repositories_sha = _sha256(_read(ROOT, REPOSITORIES))
    for name, begin, end in blocks:
        assert end is not None, f"table {name}: its end marker"
        inner = [lines[k] for k in range(begin + 1, end) if lines[k].strip()]
        assert inner, f"table {name}: empty"
        caption = inner[0]
        assert services_sha in caption and repositories_sha in caption, f"table {name}: caption carries both digests"
        assert _table_rows(lines, begin, end), f"table {name}: no rows"


def test_fixed_adr_span_sentence():
    """Design section 11, errata 2: the ADR gains one sentence beside the tables (compared with whitespace folded)."""
    text = " ".join(_read(ROOT, ADR).decode("utf-8").split())
    assert SPAN_SENTENCE in text, "the ADR's content-location sentence"


# ------------------------------------------------------------------ one or more mutations per rule

MUTATIONS = []


def mutation(rule: str, name: str):
    def register(fn):
        MUTATIONS.append(pytest.param(rule, fn, id=f"{rule}-{name}"))
        return fn
    return register


def _edit(work: Copy, fn) -> None:
    doc = work.doc()
    fn(doc)
    work.put(doc)


# R1 shape: closed objects and member types; every enum value in its constant.

@mutation("R1", "unknown-top-member")
def _(w):
    _edit(w, lambda d: d.__setitem__("oracleUnknown", True))


@mutation("R1", "unknown-deployable-member")
def _(w):
    _edit(w, lambda d: _dep(d, "inference-api").__setitem__("oracleUnknown", "x"))


@mutation("R1", "unknown-span-member")
def _(w):
    _edit(w, lambda d: _dep(d, "inference-api")["source"].__setitem__("oracleUnknown", "x"))


@mutation("R1", "unknown-owner-member")
def _(w):
    _edit(w, lambda d: _exc(d, "ai-gateway")["owner"].__setitem__("oracleUnknown", "x"))


@mutation("R1", "plane-outside-PLANES")
def _(w):
    _edit(w, lambda d: _dep(d, "control-web").__setitem__("plane", "MANAGEMENT"))


@mutation("R1", "language-outside-LANGUAGES")
def _(w):
    _edit(w, lambda d: _dep(d, "inference-api").__setitem__("plannedLanguage", "CPP"))


@mutation("R1", "status-outside-STATUSES")
def _(w):
    _edit(w, lambda d: _dep(d, "ai-gateway").__setitem__("status", "EXCEPTION"))


@mutation("R1", "planeSource-outside-PLANE_SOURCES")
def _(w):
    _edit(w, lambda d: _dep(d, "inference-api").__setitem__("planeSource", "INFERRED"))


@mutation("R1", "repository-language-outside-LANGUAGES")
def _(w):
    _edit(w, lambda d: _repo(d, "mas-harness-operator")["languages"].append("CPP"))


@mutation("R1", "member-type")
def _(w):
    def fn(d):
        span = _dep(d, "inference-api")["source"]
        span["lines"] = "-".join(str(n) for n in span["lines"])
    _edit(w, fn)


# R2 catalogues and policy.

@mutation("R2", "services-byte-changed")
def _(w):
    w.write(SERVICES, w.read(SERVICES) + b"\n")


@mutation("R2", "repositories-byte-changed")
def _(w):
    w.write(REPOSITORIES, w.read(REPOSITORIES) + b"\n")


@mutation("R2", "catalogue-pin-changed")
def _(w):
    def fn(d):
        entry = _row(_rows(d, "catalogues"), "path", REPOSITORIES)
        entry["sha256"] = _flip_hex(entry["sha256"])
    _edit(w, fn)


@mutation("R2", "policySha256-changed")
def _(w):
    _edit(w, lambda d: d.__setitem__("policySha256", _flip_hex(d["policySha256"])))


@mutation("R2", "adr-policy-line-one-character")
def _(w):
    lines = _text_lines(w.read(ADR).decode("utf-8"))
    i = _policy_index(lines)
    body = lines[i].rstrip("\n")
    lines[i] = body[:-1] + ("!" if body[-1] != "!" else ".") + lines[i][len(body):]
    w.write(ADR, "".join(lines).encode("utf-8"))


@mutation("R2", "services-counts-total-repinned")
def _(w):
    w.replace(SERVICES, b"\n  total: 28\n", b"\n  total: 29\n")
    w.repin(SERVICES)


@mutation("R2", "services-duplicate-id-repinned")
def _(w):
    w.replace(SERVICES, b"\n  - id: bundle-verifier\n", b"\n  - id: otel-collector\n")
    w.repin(SERVICES)


@mutation("R2", "repositories-duplicate-id-repinned")
def _(w):
    w.replace(REPOSITORIES, b"\n  - id: distribution\n", b"\n  - id: operator\n")
    w.repin(REPOSITORIES)


# R3 deployables: the catalogue's 28 ids once each; owner and kind; (status, plane, planeSource, plannedLanguage).

@mutation("R3", "row-dropped")
def _(w):
    _edit(w, lambda d: _rows(d, "deployables").remove(_dep(d, "ingest-worker")))


@mutation("R3", "row-duplicated")
def _(w):
    _edit(w, lambda d: _rows(d, "deployables").append(copy.deepcopy(_dep(d, "inference-api"))))


@mutation("R3", "status-pending-relabelled-AS_PLANNED")
def _(w):
    _edit(w, lambda d: _dep(d, "tool-broker").__setitem__("status", "AS_PLANNED"))


@mutation("R3", "status-no-default-relabelled-AS_PLANNED")
def _(w):
    _edit(w, lambda d: _dep(d, "ingest-worker").__setitem__("status", "AS_PLANNED"))


@mutation("R3", "status-as-planned-relabelled-NO_STATED_DEFAULT")
def _(w):
    _edit(w, lambda d: _dep(d, "otel-collector").__setitem__("status", "NO_STATED_DEFAULT"))


@mutation("R3", "plane-UNSTATED-controller-relabelled-CONTROL")
def _(w):
    _edit(w, lambda d: _dep(d, "connector-controller").update(plane="CONTROL", planeSource="KIND_RULE"))


@mutation("R3", "plane-UNSTATED-api-relabelled-DATA")
def _(w):
    _edit(w, lambda d: _dep(d, "inference-api").update(plane="DATA", planeSource="KIND_RULE"))


@mutation("R3", "planeSource-operator-relabelled-KIND_RULE")
def _(w):
    _edit(w, lambda d: _dep(d, "operator").__setitem__("planeSource", "KIND_RULE"))


@mutation("R3", "plannedLanguage-r09-relabelled-UPSTREAM_OWN")
def _(w):
    def fn(d):
        row = _dep(d, "governance-service")
        evidence = row["source"]["evidence"]
        if "Python" not in evidence:
            pytest.fail("ORACLE-SETUP: governance-service's evidence has no 'Python' token to relabel")
        evidence[evidence.index("Python")] = "upstream"
        row["plannedLanguage"] = "UPSTREAM_OWN"
    _edit(w, fn)


@mutation("R3", "ownerRepository-changed")
def _(w):
    _edit(w, lambda d: _dep(d, "inference-api").__setitem__("ownerRepository", "mas-harness-runtime-plane"))


@mutation("R3", "kind-changed")
def _(w):
    _edit(w, lambda d: _dep(d, "inference-api").__setitem__("kind", "gateway"))


# R4 repositories: the catalogue's 13; rNumber from the plan name; the first span is the plan; REPO_LANGUAGES.

@mutation("R4", "rNumber-swapped")
def _(w):
    def fn(d):
        a, b = _repo(d, "mas-harness-control-plane"), _repo(d, "mas-harness-runtime-plane")
        a["rNumber"], b["rNumber"] = b["rNumber"], a["rNumber"]
    _edit(w, fn)


@mutation("R4", "R10-without-RUST")
def _(w):
    _edit(w, lambda d: _repo(d, "mas-harness-operator")["languages"].remove("RUST"))


@mutation("R4", "R12-without-RUST")
def _(w):
    _edit(w, lambda d: _repo(d, "mas-harness-conformance-labs")["languages"].remove("RUST"))


@mutation("R4", "R02-with-GO")
def _(w):
    _edit(w, lambda d: _repo(d, "mas-harness-sdks")["languages"].append("GO"))


@mutation("R4", "name-changed")
def _(w):
    _edit(w, lambda d: _repo(d, "mas-harness-model-plane").__setitem__("name", "mas-harness-models"))


@mutation("R4", "row-dropped")
def _(w):
    _edit(w, lambda d: _rows(d, "repositories").remove(_repo(d, "mas-harness-distribution")))


@mutation("R4", "first-span-not-the-plan")
def _(w):
    _edit(w, lambda d: _repo(d, "mas-harness-operator")["sources"].reverse())


# R5 sources, as errata 2 states it: each span located by content (a block of exactly last - first + 1 whole lines
# with the pinned sha256, anywhere in the file); its evidence, id and language tokens and toolchain in that block.

def _span_of(w, ident):
    span = _dep(w.doc(), ident)["source"]
    if not _safe_rel(span.get("path")):
        pytest.fail(f"ORACLE-SETUP: {ident}'s span path is not a relative path")
    return span


def _located(w, span) -> tuple:
    raw = w.read(span["path"])
    start = _locate(raw, span)
    if start is None:
        pytest.fail("ORACLE-SETUP: the span is not found by content in the pristine copy")
    return _lines(raw), start, _span_count(span)


@mutation("R5", "cited-text-one-character-changed")
def _(w):
    span = _span_of(w, "inference-api")
    parts, start, _ = _located(w, span)
    parts[start] = _change_one_byte(parts[start])
    w.write(span["path"], b"".join(parts))


@mutation("R5", "span-line-count-changed-in-data")
def _(w):
    def fn(d):
        span = _dep(d, "inference-api")["source"]
        span["lines"] = [span["lines"][0], span["lines"][1] + 1]
    _edit(w, fn)


@mutation("R5", "span-line-count-changed-in-source")
def _(w):
    span = _span_of(w, "operator")
    parts, start, count = _located(w, span)
    if count < 2:
        pytest.fail("ORACLE-SETUP: the operator's span has one line")
    parts.insert(start + 1, b"\n")
    w.write(span["path"], b"".join(parts))


@mutation("R5", "evidence-removed-from-source-repinned")
def _(w):
    span = _span_of(w, "inference-api")
    path = span["path"]
    doc = w.doc()
    before = w.read(path)
    others = [(s, _locate(before, s)) for s in _all_spans(doc) if s.get("path") == path]
    parts, start, count = _located(w, span)
    token = b"`inference-api`"
    if not any(token in parts[k] for k in range(start, start + count)):
        pytest.fail("ORACLE-SETUP: the id token is not in inference-api's located span")
    for k in range(start, start + count):
        parts[k] = parts[k].replace(token, b"`inference-svc`")
    w.write(path, b"".join(parts))
    for other, at in others:
        if at is not None:
            other["sha256"] = _sha256(b"".join(parts[at:at + _span_count(other)]))
    w.put(doc)


@mutation("R5", "evidence-lacks-id-token")
def _(w):
    _edit(w, lambda d: _dep(d, "inference-api")["source"]["evidence"].remove("`inference-api`"))


@mutation("R5", "evidence-lacks-language-token")
def _(w):
    _edit(w, lambda d: _dep(d, "inference-api")["source"]["evidence"].remove("Python"))


@mutation("R5", "deployable-toolchain-not-in-span")
def _(w):
    _edit(w, lambda d: _dep(d, "inference-api").__setitem__("toolchain", _dep(d, "inference-api")["toolchain"]
                                                            + " (oracle)"))


@mutation("R5", "repository-toolchain-not-in-span")
def _(w):
    _edit(w, lambda d: _repo(d, "mas-harness-model-plane").__setitem__(
        "toolchain", _repo(d, "mas-harness-model-plane")["toolchain"] + " (oracle)"))


@mutation("R5", "span-path-missing")
def _(w):
    _edit(w, lambda d: _dep(d, "inference-api")["source"].__setitem__("path", PLANS + "/06-oracle-missing.md"))


# R6 outside the catalogue: the closed id set; (ownerRepository, plannedLanguage); the language token.

@mutation("R6", "id-added")
def _(w):
    def fn(d):
        row = copy.deepcopy(_out(d, "typescript-sdk"))
        row["id"] = "browser-extension"
        _rows(d, "outsideCatalogue").append(row)
    _edit(w, fn)


@mutation("R6", "id-removed")
def _(w):
    _edit(w, lambda d: _rows(d, "outsideCatalogue").remove(_out(d, "typescript-sdk")))


@mutation("R6", "id-renamed")
def _(w):
    _edit(w, lambda d: _out(d, "model-backends").__setitem__("id", "model-backend-images"))


@mutation("R6", "owner-changed")
def _(w):
    def fn(d):
        a, b = _out(d, "reference-channel-ui"), _out(d, "typescript-sdk")
        if a["ownerRepository"] == b["ownerRepository"]:
            pytest.fail("ORACLE-SETUP: the two owners are equal")
        a["ownerRepository"], b["ownerRepository"] = b["ownerRepository"], a["ownerRepository"]
    _edit(w, fn)


@mutation("R6", "r12-native-probes-relabelled-PYTHON")
def _(w):
    _edit(w, lambda d: _out(d, "r12-native-probes").__setitem__("plannedLanguage", "PYTHON"))


@mutation("R6", "native-roles-relabelled-GO")
def _(w):
    _edit(w, lambda d: _out(d, "native-host-enforcement-roles").__setitem__("plannedLanguage", "GO"))


# R7 exceptions: one per pending row and none otherwise; owner; packet; languages; PENDING: evidence.

@mutation("R7", "exception-removed")
def _(w):
    _edit(w, lambda d: _rows(d, "exceptions").remove(_exc(d, "tool-broker")))


@mutation("R7", "exception-duplicated")
def _(w):
    _edit(w, lambda d: _rows(d, "exceptions").append(copy.deepcopy(_exc(d, "ai-gateway"))))


@mutation("R7", "exception-for-a-no-default-row")
def _(w):
    def fn(d):
        row = copy.deepcopy(_exc(d, "connector-controller"))
        row["deployable"] = "ingest-worker"
        row["owner"] = {"repository": "mas-harness-knowledge-plane", "packet": "KN-DATA-001"}
        row["reviewTrigger"] = row["reviewTrigger"].replace("connector-controller", "ingest-worker")
        _rows(d, "exceptions").append(row)
    _edit(w, fn)


@mutation("R7", "packet-changed")
def _(w):
    _edit(w, lambda d: _exc(d, "ai-gateway")["owner"].__setitem__("packet", "RUN-EXP-001"))


@mutation("R7", "owner-repository-changed")
def _(w):
    _edit(w, lambda d: _exc(d, "ai-gateway")["owner"].__setitem__("repository", "mas-harness-execution-plane"))


@mutation("R7", "defaultLanguage-not-GO")
def _(w):
    _edit(w, lambda d: _exc(d, "protocol-gateway").__setitem__("defaultLanguage", "PYTHON"))


@mutation("R7", "plannedLanguage-differs")
def _(w):
    _edit(w, lambda d: _exc(d, "protocol-gateway").__setitem__("plannedLanguage", "GO"))


def _evidence(d, ident) -> str:
    text = _exc(d, ident)["evidence"]
    if not text.startswith(PENDING_PREFIX):
        pytest.fail(f"ORACLE-SETUP: {ident}'s evidence does not begin {PENDING_PREFIX}")
    return text


@mutation("R7", "evidence-without-PENDING")
def _(w):
    _edit(w, lambda d: _exc(d, "experience-gateway").__setitem__(
        "evidence", _evidence(d, "experience-gateway")[len(PENDING_PREFIX):].lstrip()))


@mutation("R7", "evidence-lowercase-pending")
def _(w):
    _edit(w, lambda d: _exc(d, "experience-gateway").__setitem__(
        "evidence", "pending:" + _evidence(d, "experience-gateway")[len(PENDING_PREFIX):]))


@mutation("R7", "evidence-names-neither-decision-nor-packet")
def _(w):
    _edit(w, lambda d: _exc(d, "tool-broker").__setitem__("evidence", PENDING_PREFIX + " a later review."))


# R8 the ADR's tables: each block equals the deterministic rendering of the data.

def _adr_lines(w) -> list:
    return _text_lines(w.read(ADR).decode("utf-8"))


def _block(lines: list, index: int) -> tuple:
    blocks = _blocks(lines)
    if len(blocks) != 4 or any(end is None for _, _, end in blocks):
        pytest.fail(f"ORACLE-SETUP: the ADR does not hold four closed table blocks ({len(blocks)})")
    return blocks[index]


def _edit_row(index: int):
    def fn(w):
        lines = _adr_lines(w)
        _, begin, end = _block(lines, index)
        rows = _table_rows(lines, begin, end)
        if not rows:
            pytest.fail("ORACLE-SETUP: the table has no rows")
        lines[rows[-1]] = _change_letter(lines[rows[-1]])
        w.write(ADR, "".join(lines).encode("utf-8"))
    return fn


for _k in range(4):
    mutation("R8", f"table-{_k + 1}-row-edited")(_edit_row(_k))


def _largest_block(lines: list) -> tuple:
    blocks = [_block(lines, k) for k in range(4)]
    return max(blocks, key=lambda b: len(_table_rows(lines, b[1], b[2])))


@mutation("R8", "deployables-row-deleted")
def _(w):
    lines = _adr_lines(w)
    _, begin, end = _largest_block(lines)
    del lines[_table_rows(lines, begin, end)[-1]]
    w.write(ADR, "".join(lines).encode("utf-8"))


@mutation("R8", "deployables-rows-reordered")
def _(w):
    lines = _adr_lines(w)
    _, begin, end = _largest_block(lines)
    rows = _table_rows(lines, begin, end)
    a, b = rows[-2], rows[-1]
    if lines[a] == lines[b]:
        pytest.fail("ORACLE-SETUP: the last two rows are equal")
    lines[a], lines[b] = lines[b], lines[a]
    w.write(ADR, "".join(lines).encode("utf-8"))


@mutation("R8", "caption-digest-changed")
def _(w):
    lines = _adr_lines(w)
    _, begin, end = _block(lines, 0)
    k = next((k for k in range(begin + 1, end) if lines[k].strip()), None)
    if k is None:
        pytest.fail("ORACLE-SETUP: the first table has no caption")
    digest = _sha256(w.read(SERVICES))
    if digest in lines[k]:
        lines[k] = lines[k].replace(digest, _flip_hex(digest))
    else:
        lines[k] = _change_letter(lines[k])
    w.write(ADR, "".join(lines).encode("utf-8"))


@pytest.mark.parametrize("rule, mutate", MUTATIONS)
def test_mutation_refused(oracle_copy, rule, mutate):
    mutate(oracle_copy)
    _refused(oracle_copy, rule)


# ------------------------------------------------------------------ errata 2: a shift is accepted

SHIFT_LINE = b"Oracle shift line.\n"


def _shift_added_above_r00(w):
    rel = _plan("Harness-Engineering")
    w.write(rel, SHIFT_LINE + w.read(rel))


def _shift_added_above_span(w):
    rel = _span_of(w, "inference-api")["path"]
    w.write(rel, SHIFT_LINE + w.read(rel))


def _shift_removed_above_span(w):
    rel = _span_of(w, "inference-api")["path"]
    raw = w.read(rel)
    starts = [_locate(raw, s) for s in _all_spans(w.doc()) if s.get("path") == rel]
    if not starts or any(s is None or s == 0 for s in starts):
        pytest.fail("ORACLE-SETUP: a span on the file starts at its first line, or is not located")
    w.write(rel, b"".join(_lines(raw)[1:]))


SHIFTS = {
    "line-added-above-the-R00-plan-spans": _shift_added_above_r00,
    "line-added-above-a-span": _shift_added_above_span,
    "line-removed-above-a-span": _shift_removed_above_span,
}


@pytest.mark.parametrize("name", sorted(SHIFTS))
def test_shift_accepted(oracle_copy, name):
    """Errata 2: "A shift of the block (lines added or removed above it) is accepted"."""
    SHIFTS[name](oracle_copy)
    rc, out = oracle_copy.check()
    assert rc == 0, f"errata 2 accepts a shift; {name} gave exit {rc}:\n{_tail(out)}"


# Errata 2: "lines record the block's position at the base, and are for display only". A change to the data's lines
# alone, with the line count kept, is not refused by R5; the rendered tables (R8) may show it.
LINES_ONLY = {
    "shifted-up-one": lambda lines: [lines[0] - 1, lines[1] - 1],
    "moved-past-the-end": lambda lines: [100000, 100000 + lines[1] - lines[0]],
}


@pytest.mark.parametrize("name", sorted(LINES_ONLY))
def test_lines_only_not_refused_by_r5(oracle_copy, oracle_pristine, name):
    def fn(d):
        span = _dep(d, "inference-api")["source"]
        span["lines"] = LINES_ONLY[name](span["lines"])
    _edit(oracle_copy, fn)
    rc, out = oracle_copy.check()
    _, pristine_out = oracle_pristine
    assert "Traceback (most recent call last)" not in out, f"{name}: a crash:\n{_tail(out)}"
    assert rc in (0, 1), f"{name}: exit {rc}:\n{_tail(out)}"
    assert not _new_rule_lines(out, pristine_out, "R5"), f"{name}: refused by R5:\n{_tail(out)}"
    if rc == 1:
        named = {r for r in RULES if _new_rule_lines(out, pristine_out, r)}
        assert named == {"R8"}, f"{name}: refused by {sorted(named)}, where only R8 may show it:\n{_tail(out)}"


# ------------------------------------------------------------------ the parse rules (design section 4)

_FIRST_LINE = re.compile(rb'("lines"\s*:\s*\[\s*)(\d+)')
_TRIGGER = re.compile(rb'("reviewTrigger"\s*:\s*")')


def _sub(pattern, raw: bytes, fn) -> bytes:
    new, count = pattern.subn(fn, raw, count=1)
    if count != 1:
        pytest.fail("ORACLE-SETUP: the data has no place for the parse mutation")
    return new


def _duplicate_key(raw: bytes) -> bytes:
    adr = json.loads(raw.decode("utf-8"))["adr"]
    start = raw.index(b"{") + 1
    return raw[:start] + b'"adr": ' + json.dumps(adr).encode("utf-8") + b"," + raw[start:]


PARSE = {
    "duplicate-key": _duplicate_key,
    "byte-order-mark": lambda raw: b"\xef\xbb\xbf" + raw,
    "integral-float": lambda raw: _sub(_FIRST_LINE, raw, lambda m: m.group(1) + m.group(2) + b".0"),
    "integral-float-exponent": lambda raw: _sub(_FIRST_LINE, raw, lambda m: m.group(1) + m.group(2) + b"e0"),
    "non-finite-nan": lambda raw: _sub(_FIRST_LINE, raw, lambda m: m.group(1) + b"NaN"),
    "non-finite-infinity": lambda raw: _sub(_FIRST_LINE, raw, lambda m: m.group(1) + b"Infinity"),
    "oversized-integer": lambda raw: _sub(_FIRST_LINE, raw, lambda m: m.group(1) + b"1000000000001"),
    "lone-surrogate": lambda raw: _sub(_TRIGGER, raw, lambda m: m.group(1) + b"\\ud800"),
    "not-utf-8": lambda raw: _sub(_TRIGGER, raw, lambda m: m.group(1) + b"\xff"),
}


@pytest.mark.parametrize("name", sorted(PARSE))
def test_parse_refused(oracle_copy, name):
    oracle_copy.write(DATA, PARSE[name](oracle_copy.read(DATA)))
    rc, out = oracle_copy.check()
    assert rc == 1, f"parse rule {name}: expected exit 1, got {rc}:\n{_tail(out)}"
    assert "Traceback (most recent call last)" not in out, f"parse rule {name}: a crash, not a refusal:\n{_tail(out)}"
