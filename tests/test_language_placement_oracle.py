"""Re-issued D5a oracle for MET-GOV-005 (TECH-TRUTH-001): the language-placement record, schema v2.

Every expectation in this module comes from the closed design (revision 3: sections 0a, 2, 3, 5 and 6, and Appendices
A to C) and from the source texts that the design cites. None comes from the checker, its data or its tests.

The checker is reached only through its published command line, ``python3 scripts/language_placement.py check --root
<dir>``, run as a subprocess with ``sys.executable``. The one exception is the design's two direct R14 rows (section 5,
rows 52 and 53), which load ``_r14`` from the file by path.

Every mutation runs on its own real copy of the inputs the design names for the checker (the record, the three
catalogs, the ADRs, the repository plans, the harness documents, the alpha-2 records, the checker and
``scripts/safe_yaml.py``). Copies are made with ``shutil.copytree`` and its default ``copy2`` (never links), and each is
removed at teardown, pass or fail. A "constant patch" edits the copy's checker constant and the copy's data together.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import inspect
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

DATA = "architecture/language-placement.json"
CHECKER = "scripts/language_placement.py"
SAFE_YAML = "scripts/safe_yaml.py"
SERVICES = "architecture/services.yaml"
REPOSITORIES = "architecture/repositories.yaml"
PROVIDERS = "architecture/providers.yaml"
ADR10 = "docs/adr/0010-language-placement.md"
ADR11 = "docs/adr/0011-h10-execution-authority.md"

COPY_FILES = (DATA, SERVICES, REPOSITORIES, PROVIDERS, CHECKER, SAFE_YAML)
COPY_DIRS = ("docs/adr", "docs/alpha-2", "docs/harnesses", "docs/repositories")
SKIP_TOKENS = ("w" + "03", "l" + "pk")  # lane-independence filter: such paths are never copied or read

# ------------------------------------------------------------------------------------------- the design's fixed facts

SCHEMA_V1 = "planeon.internal.language-placement/v1"
SCHEMA_V2 = "planeon.internal.language-placement/v2"
SCHEMA_V3 = "planeon.internal.language-placement/v3"

SPAN_MEMBERS = {"path", "section", "lines", "sha256", "evidence"}
TOP_MEMBERS = {"schemaVersion", "adr", "policySha256", "catalogues", "repositories", "deployables", "outsideCatalogue",
               "exceptions", "baselineBindings", "h10Sources"}
REPOSITORY_MEMBERS = {"id", "name", "rNumber", "languages", "toolchain", "sources"}
DEPLOYABLE_V1_MEMBERS = {"id", "ownerRepository", "kind", "plannedLanguage", "toolchain", "plane", "planeSource",
                         "status", "source"}
TECH_MEMBERS = {"runtime", "frameworks", "packaging", "upstream", "implementationStatus", "decision"}
DEPLOYABLE_MEMBERS = DEPLOYABLE_V1_MEMBERS | TECH_MEMBERS | {"frameworksSources"}
OUTSIDE_V1_MEMBERS = {"id", "ownerRepository", "plannedLanguage", "sources"}
NATIVE_MEMBERS = OUTSIDE_V1_MEMBERS | TECH_MEMBERS
NATIVE_ROWS = ("native-host-enforcement-roles", "r12-native-probes")
OTHER_OUTSIDE_ROWS = ("reference-channel-ui", "typescript-sdk", "model-backends")

CATALOGUES_ORDER = [SERVICES, REPOSITORIES, PROVIDERS]

ADR10_ID = "docs/adr/0010-language-placement.md"
ADR11_ID = "docs/adr/0011-h10-execution-authority.md"
HOTPATH = "LANG-HOTPATH-DECISION-001"
KN_DATA = "KN-DATA-001"

P04 = "docs/repositories/04-mas-harness-control-plane.md"
P05 = "docs/repositories/05-mas-harness-runtime-plane.md"
P06 = "docs/repositories/06-mas-harness-model-plane.md"
P07 = "docs/repositories/07-mas-harness-knowledge-plane.md"
P08 = "docs/repositories/08-mas-harness-execution-plane.md"
P09 = "docs/repositories/09-mas-harness-trust-plane.md"
P10 = "docs/repositories/10-mas-harness-operator.md"

TOOLCHAIN_HEADING = "## Deployables and toolchain"

GO = "Go 1.26.7"
PY = "Python 3.12.14"
NODE = "Node 24.20.0 LTS"
OCI = ["OCI_IMAGE"]
CHART = ["HELM_CHART", "OCI_IMAGE"]

F_R10_152 = ["controller-runtime", "Kubebuilder/envtest", "Helm 4.2.0", "Cosign 3.1.3", "Kustomize 5.8.1"]
F_R09_90 = ["FastAPI", "Pydantic v2", "psycopg 3", "cryptography", "HTTPX", "OpenTelemetry", "jsonschema", "pytest"]
F_R08_101 = ["FastAPI", "Pydantic v2", "psycopg 3", "jsonschema", "cryptography", "HTTPX", "OpenTelemetry",
             "MCP SDK compatible with 2026-07-28 plus 2025-11-25", "A2A v1"]
F_R07_119 = ["FastAPI", "Pydantic v2", "psycopg 3", "PostgreSQL/pgvector", "RDFLib", "pySHACL", "jsonschema", "HTTPX",
             "cryptography", "OpenTelemetry"]
F_R06_99 = ["FastAPI", "Pydantic v2", "Uvicorn", "HTTPX", "cryptography", "structlog", "SSE", "OpenTelemetry"]
F_R05_88 = ["FastAPI/Starlette", "Pydantic v2", "HTTPX", "psycopg 3", "cryptography", "OpenTelemetry", "SSE support"]
F_R04_102 = ["Next.js 16.3.3 Active LTS with the App Router", "React 19.2", "TypeScript 5", "Prisma 6.19.3", "PostgreSQL",
             "AJV 8.20.0", "Vitest", "Playwright"]

# Appendix A: id -> (runtime, frameworks, [(plan, located line)], packaging, upstream, implementationStatus, decision)
APPENDIX_A = {
    "bundle-verifier": (GO, F_R10_152, [(P10, 152)], OCI, None, "PLANNED", ADR10_ID),
    "otel-collector": (None, [], [], CHART, "otel/opentelemetry-collector-contrib", "UPSTREAM_MANAGED", ADR10_ID),
    "operator": (GO, F_R10_152, [(P10, 152)], CHART, None, "PLANNED", ADR10_ID),
    "policy-decision": (PY, F_R09_90 + ["OPA"], [(P09, 90), (P09, 100)], OCI, None, "PLANNED", ADR10_ID),
    "sandbox-runner": (PY, F_R08_101, [(P08, 101)], OCI, None, "PLANNED", ADR10_ID),
    "fleet-sync-agent": (GO, F_R10_152, [(P10, 152)], OCI, None, "PLANNED", ADR10_ID),
    "guardrail-service": (PY, F_R09_90, [(P09, 90)], OCI, None, "PLANNED", ADR10_ID),
    "usage-ledger": (PY, F_R09_90, [(P09, 90)], OCI, None, "PLANNED", ADR10_ID),
    "governance-service": (PY, F_R09_90, [(P09, 90)], OCI, None, "PLANNED", ADR10_ID),
    "domain-service": (PY, F_R07_119, [(P07, 119)], OCI, None, "PLANNED", ADR10_ID),
    "registry-service": (PY, F_R09_90, [(P09, 90)], OCI, None, "PLANNED", ADR10_ID),
    "inference-api": (PY, F_R06_99, [(P06, 99)], OCI, None, "PLANNED", ADR10_ID),
    "connector-controller": (PY, F_R07_119, [(P07, 119)], OCI, None, "PLANNED", KN_DATA),
    "memory-service": (PY, F_R07_119, [(P07, 119)], OCI, None, "PLANNED", ADR10_ID),
    "control-web": (NODE, F_R04_102, [(P04, 102)], CHART, None, "PLANNED", ADR10_ID),
    "ingest-worker": (PY, F_R07_119, [(P07, 119)], OCI, None, "PLANNED", ADR10_ID),
    "retrieval-service": (PY, F_R07_119, [(P07, 119)], OCI, None, "PLANNED", ADR10_ID),
    "protocol-gateway": (PY, F_R08_101, [(P08, 101)], OCI, None, "PLANNED", HOTPATH),
    "evidence-service": (PY, F_R09_90, [(P09, 90)], OCI, None, "PLANNED", ADR10_ID),
    "profile-compiler-worker": (PY, ["`uv` 0.12.7"], [(P04, 103)], OCI, None, "PLANNED", ADR10_ID),
    "index-worker": (PY, F_R07_119, [(P07, 119)], OCI, None, "PLANNED", ADR10_ID),
    "orchestration-api": (PY, F_R08_101, [(P08, 101)], OCI, None, "PLANNED", ADR11_ID),
    "decision-service": (PY, F_R08_101, [(P08, 101)], OCI, None, "PLANNED", ADR10_ID),
    "assurance-worker": (PY, F_R09_90, [(P09, 90)], OCI, None, "PLANNED", ADR10_ID),
    "tool-broker": (PY, F_R08_101, [(P08, 101)], OCI, None, "PLANNED", HOTPATH),
    "orchestration-worker": (PY, F_R08_101, [(P08, 101)], OCI, None, "PLANNED", ADR11_ID),
    "ai-gateway": (PY, F_R05_88, [(P05, 88)], OCI, None, "PLANNED", HOTPATH),
    "experience-gateway": (PY, F_R05_88, [(P05, 88), (P05, 89)], OCI, None, "PLANNED", HOTPATH),
}
NATIVE_VALUES = {"runtime": "Rust", "frameworks": [], "packaging": ["NATIVE_BINARY"], "upstream": None,
                 "implementationStatus": "PLANNED", "decision": ADR10_ID}

STEMS = [
    "execution.ml-decision", "execution.orchestration", "execution.protocol-interoperability",
    "execution.tool-skill-sandbox", "knowledge.data-integration", "knowledge.domain-semantic",
    "knowledge.memory-state", "knowledge.retrieval-context", "runtime.ai-gateway", "runtime.experience",
    "runtime.infrastructure", "runtime.model-inference", "trust.evaluation-assurance", "trust.governance-agentops",
    "trust.observability-finops", "trust.security-safety",
]

CM, OA, PL, DF = "CATALOG_MODULE", "OPTIONAL_ADAPTER", "PLAN_LIBRARY", "DEFERRED"

# Appendix B, in order: (harness, baseline, kind, target)
APPENDIX_B = [
    ("execution.ml-decision", "scikit-learn/scikit-learn", CM, {"record": "provider.execution.decision-sklearn", "token": "planeon.sklearn"}),
    ("execution.ml-decision", "microsoft/onnxruntime", CM, {"record": "provider.execution.decision-onnx", "token": "planeon.onnx"}),
    ("execution.orchestration", "planeon.orchestrator.postgres", CM, {"record": "module.execution.orchestration.orchestration-worker", "token": "planeon.orchestrator.postgres"}),
    ("execution.orchestration", "temporalio/temporal", DF, {"item": "EXEC-TEMPORAL-001"}),
    ("execution.protocol-interoperability", "modelcontextprotocol/python-sdk", CM, {"record": "provider.execution.protocol-mcp", "token": "planeon.mcp"}),
    ("execution.protocol-interoperability", "a2aproject/a2a-python", CM, {"record": "provider.execution.protocol-a2a", "token": "planeon.a2a"}),
    ("execution.tool-skill-sandbox", "google/gvisor", CM, {"record": "provider.execution.sandbox-gvisor", "token": "planeon.sandbox.gvisor"}),
    ("execution.tool-skill-sandbox", "bytecodealliance/wasmtime", CM, {"record": "provider.execution.sandbox-wasmtime", "token": "planeon.sandbox.wasmtime"}),
    ("knowledge.data-integration", "trinodb/trino", DF, {"item": "KN-DATA-ADOPT-001"}),
    ("knowledge.data-integration", "fivetran/great_expectations", DF, {"item": "KN-DATA-ADOPT-001"}),
    ("knowledge.data-integration", "OpenLineage/OpenLineage", DF, {"item": "KN-DATA-ADOPT-001"}),
    ("knowledge.domain-semantic", "RDFLib/rdflib", CM, {"record": "module.knowledge.domain-semantic.domain-service", "token": "planeon.rdflib"}),
    ("knowledge.domain-semantic", "RDFLib/pySHACL", CM, {"record": "module.knowledge.domain-semantic.domain-service", "token": "planeon.pyshacl"}),
    ("knowledge.memory-state", "mem0ai/mem0", DF, {"item": "KN-MEM-ADOPT-001"}),
    ("knowledge.retrieval-context", "run-llama/llama_index", DF, {"item": "KN-RET-ADOPT-001"}),
    ("knowledge.retrieval-context", "pgvector/pgvector", CM, {"record": "external.pgvector", "token": "tenant.pgvector"}),
    ("runtime.ai-gateway", "BerriAI/litellm", OA, {"record": "provider.planeon.litellm-local", "token": "planeon.litellm-local"}),
    ("runtime.experience", "ag-ui-protocol/ag-ui", OA, {"record": "provider.planeon.experience-agui", "token": "planeon.experience.agui"}),
    ("runtime.experience", "CopilotKit/CopilotKit", DF, {"item": "RUN-UI-ADOPT-001"}),
    ("runtime.infrastructure", "kubernetes/kubernetes", CM, {"record": "provider.runtime.infrastructure.kubernetes-upstream", "token": "kubernetes.upstream"}),
    ("runtime.infrastructure", "helm/helm", PL, {"span": (P10, 152, "Helm 4.2.0")}),
    ("runtime.model-inference", "ollama/ollama", CM, {"record": "provider.planeon.ollama", "token": "planeon.ollama"}),
    ("runtime.model-inference", "ggml-org/llama.cpp", CM, {"record": "provider.planeon.llamacpp", "token": "planeon.llamacpp"}),
    ("runtime.model-inference", "vllm-project/vllm", CM, {"record": "provider.planeon.vllm", "token": "planeon.vllm"}),
    ("trust.evaluation-assurance", "UKGovernmentBEIS/inspect_ai", DF, {"item": "TRUST-EVAL-ADOPT-001"}),
    ("trust.governance-agentops", "open-policy-agent/opa", CM, {"record": "external.opa-engine", "token": "opa"}),
    ("trust.governance-agentops", "mlflow/mlflow", DF, {"item": "TRUST-GOV-ADOPT-001"}),
    ("trust.observability-finops", "open-telemetry/opentelemetry-collector", CM, {"record": "module.trust.observability.otel-collector", "token": "planeon.otel"}),
    ("trust.observability-finops", "prometheus/prometheus", CM, {"record": "external.otel-backend", "token": "prometheus"}),
    ("trust.security-safety", "open-policy-agent/opa", CM, {"record": "external.opa-engine", "token": "opa"}),
    ("trust.security-safety", "data-privacy-stack/presidio", DF, {"item": "TRUST-SAFE-ADOPT-001"}),
]
KIND_COUNTS = {CM: 18, DF: 10, OA: 2, PL: 1}

DIVERGENCE_HOLDER = ("runtime.ai-gateway", "BerriAI/litellm")
DIVERGENCE = {"roadmapSelection": "Agent Router", "decisions": ["OW-D3", "H3-D1"], "deferral": "RUN-GATEWAY-ADOPT-001"}
H10_EVIDENCE = ["PostgreSQL leases/outbox", "Temporal is a separate optional provider module"]

SPAN_TOTAL = 112  # 49 v1 + 29 frameworks + 32 harness + 1 plan-library + 1 R08
R00_LINE, R00_SECTION = 1252, "## Packages, toolchain, and owned interfaces"

# Anchors in R08's plan for the section-anchoring rows (12-18): the durable-executor bullet, h10Sources.r08's block.
DURABLE = "- Baseline durable executor uses PostgreSQL leases/outbox."
SANDBOX = "- Sandbox providers:"
PY_BULLET = "- Python 3.12.14, FastAPI"

HEADING = re.compile(r"#{1,6} ")
WORD_EDGE = "A-Za-z0-9_+\\-"
REFUSED = re.compile(r"refused: (R\d+)")


# ------------------------------------------------------------------------------------------------- copies and runs

def _skipped(name: str) -> bool:
    low = name.lower()
    return any(token in low for token in SKIP_TOKENS)


def _ignore(_directory, names):
    return {name for name in names if _skipped(name)}


def _make_copy(parent: Path) -> Path:
    dest = Path(tempfile.mkdtemp(prefix="root-", dir=parent))
    for rel in COPY_DIRS:
        shutil.copytree(ROOT / rel, dest / rel, ignore=_ignore)  # default copy_function=copy2, symlinks=False
    for rel in COPY_FILES:
        (dest / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, dest / rel)
    for current, _dirs, names in os.walk(dest):  # copy2 keeps mode bits; the copy must be writable
        os.chmod(current, os.lstat(current).st_mode | 0o700)
        for name in names:
            path = os.path.join(current, name)
            os.chmod(path, os.lstat(path).st_mode | 0o600)
    return dest


def _read(path: Path) -> str:
    with open(path, encoding="utf-8", newline="") as handle:
        return handle.read()


def _split(text: str) -> list:
    parts = text.split("\n")
    lines = [part + "\n" for part in parts[:-1]]
    if parts[-1]:
        lines.append(parts[-1])
    return lines


_SERIALIZER: dict = {}


def _serializer():
    """The json.dumps form that reproduces the record's own bytes, found once from the pristine file."""
    if "dump" not in _SERIALIZER:
        raw = _read(ROOT / DATA)
        obj = json.loads(raw)
        found = None
        for indent in (2, 4, 1, None):
            for separators in (None, (",", ": "), (",", ":"), (", ", ": ")):
                for ascii_only in (False, True):
                    for sort_keys in (False, True):
                        options = dict(indent=indent, separators=separators, ensure_ascii=ascii_only,
                                       sort_keys=sort_keys)
                        text = json.dumps(obj, **options)
                        for tail in ("\n", ""):
                            if found is None and text + tail == raw:
                                found = (options, tail)
        _SERIALIZER["exact"] = found is not None
        options, tail = found or (dict(indent=2, ensure_ascii=False), "\n")
        _SERIALIZER["dump"] = lambda value: json.dumps(value, **options) + tail
    return _SERIALIZER["dump"]


class Tree:
    """One real copy of the checker's inputs."""

    def __init__(self, root: Path):
        self.root = root

    def path(self, rel: str) -> Path:
        return self.root / rel

    def read(self, rel: str) -> str:
        return _read(self.path(rel))

    def write(self, rel: str, text: str) -> None:
        with open(self.path(rel), "w", encoding="utf-8", newline="") as handle:
            handle.write(text)

    def lines(self, rel: str) -> list:
        return _split(self.read(rel))

    def write_lines(self, rel: str, lines: list) -> None:
        self.write(rel, "".join(lines))

    def digest(self, rel: str) -> str:
        return hashlib.sha256(self.path(rel).read_bytes()).hexdigest()

    def data(self) -> dict:
        return json.loads(self.read(DATA))

    def write_data(self, value: dict) -> None:
        self.write(DATA, _serializer()(value))

    def edit_data(self, change) -> None:
        value = self.data()
        change(value)
        self.write_data(value)

    def run(self) -> tuple:
        proc = subprocess.run([sys.executable, "-B", CHECKER, "check", "--root", str(self.root)], cwd=self.root,
                              capture_output=True, text=True, timeout=300)
        output = proc.stdout + proc.stderr
        if proc.returncode == 0:
            return "accepted", output
        match = REFUSED.search(output)
        if proc.returncode == 1 and match:
            return match.group(1), output
        return "exit %d" % proc.returncode, output


def _expect(tree: Tree, expected: str) -> None:
    outcome, output = tree.run()
    assert outcome == expected, "expected %s, got %s: %s" % (expected, outcome, output[-1500:])


@pytest.fixture(scope="session")
def temp_parent():
    parent = Path(tempfile.mkdtemp(prefix="lp-oracle-"))
    try:
        yield parent
    finally:
        shutil.rmtree(parent, ignore_errors=True)


@pytest.fixture
def tree(temp_parent):
    dest = _make_copy(temp_parent)
    try:
        yield Tree(dest)
    finally:
        shutil.rmtree(dest, ignore_errors=True)


# ------------------------------------------------------------------------------------------------ data accessors

def _one(items, what):
    items = list(items)
    assert len(items) == 1, "expected exactly one %s, found %d" % (what, len(items))
    return items[0]


def dep(data, ident):
    return _one((r for r in data["deployables"] if r.get("id") == ident), "deployable " + ident)


def outside(data, ident):
    return _one((r for r in data["outsideCatalogue"] if r.get("id") == ident), "outside row " + ident)


def repo(data, ident):
    return _one((r for r in data["repositories"] if r.get("id") == ident), "repository " + ident)


def entry(data, harness):
    return _one((e for e in data["baselineBindings"] if e.get("harness") == harness), "binding entry " + harness)


def _bare(value):
    return value.strip("`") if isinstance(value, str) else value


def brow(data, harness, baseline):
    return _one((r for r in entry(data, harness)["rows"] if _bare(r.get("baseline")) == baseline),
                "binding row %s %s" % (harness, baseline))


def divergence_rows(data):
    return [(e.get("harness"), r) for e in data["baselineBindings"] for r in e["rows"] if "divergence" in r]


def _walk_spans(value):
    if isinstance(value, dict):
        if set(value) == SPAN_MEMBERS:
            yield value
            return
        for item in value.values():
            yield from _walk_spans(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_spans(item)


def _first_alpha2_span(data):
    return copy.deepcopy(outside(data, "native-host-enforcement-roles")["sources"][0])


# --------------------------------------------------------------------------------------------- spans and sections

def _pair(span):
    lines = span["lines"]
    if isinstance(lines, bool):
        raise AssertionError("lines is a boolean")
    if isinstance(lines, int):
        return lines, lines
    if isinstance(lines, list) and len(lines) == 2:
        return int(lines[0]), int(lines[1])
    if isinstance(lines, str):
        first, _, last = lines.partition("-")
        return int(first), int(last or first)
    if isinstance(lines, dict):
        values = list(lines.values())
        return int(values[0]), int(values[1])
    raise AssertionError("unknown lines form %r" % (lines,))


def _with_lines(template, first, last):
    lines = template["lines"]
    if isinstance(lines, list):
        return [first, last]
    if isinstance(lines, int):
        return first
    if isinstance(lines, str):
        return "%d-%d" % (first, last) if "-" in lines else "%d" % first
    if isinstance(lines, dict):
        keys = list(lines)
        return {keys[0]: first, keys[1]: last}
    raise AssertionError("unknown lines form")


def _sha(lines, start, count):
    return hashlib.sha256("".join(lines[start:start + count]).encode("utf-8")).hexdigest()


def _headings(lines):
    return [(i, line.rstrip("\n")) for i, line in enumerate(lines) if HEADING.match(line)]


def _enclosing(lines, index):
    """The heading text enclosing 0-based line `index`, or None."""
    found = None
    for i, text in _headings(lines):
        if i < index:
            found = text
    return found


def _section_range(lines, heading):
    """(start, end) 0-based, end exclusive, for a heading text occurring exactly once; else None."""
    heads = _headings(lines)
    hits = [i for i, text in heads if text == heading]
    if len(hits) != 1:
        return None
    later = [i for i, _ in heads if i > hits[0]]
    return hits[0] + 1, (later[0] if later else len(lines))


def _matches(lines, sha, count, start=0, end=None):
    end = len(lines) if end is None else end
    return [i for i in range(start, end - count + 1) if _sha(lines, i, count) == sha]


def _locate(reader, span):
    """0-based start of the span's block inside its own section (the design's C2-2 rule), or a reason string."""
    lines = _split(reader(span["path"]))
    first, last = _pair(span)
    count = last - first + 1
    heading = span.get("section")
    if heading is None:
        hits = _matches(lines, span["sha256"], count)
        good = []
        for i in hits:
            head = _enclosing(lines, i)
            bounds = _section_range(lines, head) if head else None
            if bounds and len(_matches(lines, span["sha256"], count, *bounds)) == 1:
                good.append(i)
        return good[0] if len(good) == 1 else "no unique sectioned match (%d raw matches)" % len(hits)
    bounds = _section_range(lines, heading)
    if bounds is None:
        return "heading %r is not unique or missing" % heading
    hits = _matches(lines, span["sha256"], count, *bounds)
    if len(hits) != 1:
        return "%d matches inside %r" % (len(hits), heading)
    section_text = "".join(lines[bounds[0]:bounds[1]])
    missing = [e for e in span["evidence"] if e not in section_text]
    if missing:
        return "evidence %r not in its section" % missing
    return hits[0]


def _block_text(reader, span):
    start = _locate(reader, span)
    assert isinstance(start, int), "%s: %s" % (span["path"], start)
    first, last = _pair(span)
    return "".join(_split(reader(span["path"]))[start:start + last - first + 1]), start + 1


def _make_span(tree: Tree, rel: str, index: int, evidence: list, template: dict) -> dict:
    lines = tree.lines(rel)
    values = {"path": rel, "section": _enclosing(lines, index), "lines": _with_lines(template, index + 1, index + 1),
              "sha256": _sha(lines, index, 1), "evidence": evidence}
    return {key: values[key] for key in template}


def _whole_word(item: str, text: str) -> bool:
    return re.search("(?<![%s])%s(?![%s])" % (WORD_EDGE, re.escape(item), WORD_EDGE), text) is not None


# --------------------------------------------------------------------------- constant patches (by exact source span)

class _NotLiteral(Exception):
    pass


def _starts(src: str) -> list:
    return [0] + [i + 1 for i, ch in enumerate(src) if ch == "\n"]


def _offset(src, starts, lineno, col):
    end = starts[lineno] if lineno < len(starts) else len(src)
    line = src[starts[lineno - 1]:end]
    return starts[lineno - 1] + len(line.encode("utf-8")[:col].decode("utf-8"))


def _segment(src, node):
    starts = _starts(src)
    return _offset(src, starts, node.lineno, node.col_offset), _offset(src, starts, node.end_lineno, node.end_col_offset)


def _top_value(tree, name):
    found = None
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign):
            targets = stmt.targets
        elif isinstance(stmt, ast.AnnAssign):
            targets = [stmt.target]
        else:
            continue
        if stmt.value is not None and any(isinstance(t, ast.Name) and t.id == name for t in targets):
            found = stmt.value
    assert found is not None, "constant patch: no top-level assignment of %s" % name
    return found


def _eval(node, tree, depth=0):
    if depth > 20:
        raise _NotLiteral("too deep")
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        try:
            return _eval(_top_value(tree, node.id), tree, depth + 1)
        except AssertionError as exc:
            raise _NotLiteral(str(exc))
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        items = []
        for elt in node.elts:
            if isinstance(elt, ast.Starred):
                items.extend(_eval(elt.value, tree, depth + 1))
            else:
                items.append(_eval(elt, tree, depth + 1))
        return {ast.List: list, ast.Tuple: tuple, ast.Set: set}[type(node)](items)
    if isinstance(node, ast.Dict):
        out = {}
        for key, value in zip(node.keys, node.values):
            if key is None:
                out.update(_eval(value, tree, depth + 1))
            else:
                out[_eval(key, tree, depth + 1)] = _eval(value, tree, depth + 1)
        return out
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _eval(node.left, tree, depth + 1) + _eval(node.right, tree, depth + 1)
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and not node.keywords and len(node.args) <= 1
            and node.func.id in ("tuple", "list", "frozenset", "set", "dict")):
        arg = _eval(node.args[0], tree, depth + 1) if node.args else ()
        return {"tuple": tuple, "list": list, "frozenset": frozenset, "set": set, "dict": dict}[node.func.id](arg)
    raise _NotLiteral(ast.dump(node)[:120])


def _literal(value) -> str:
    if value is None or isinstance(value, bool):
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, list):
        return "[" + ", ".join(_literal(v) for v in value) + "]"
    if isinstance(value, tuple):
        inner = ", ".join(_literal(v) for v in value)
        return "(" + inner + ("," if len(value) == 1 else "") + ")"
    if isinstance(value, frozenset):
        return "frozenset({" + ", ".join(_literal(v) for v in sorted(value)) + "})" if value else "frozenset()"
    if isinstance(value, set):
        return "{" + ", ".join(_literal(v) for v in sorted(value)) + "}" if value else "set()"
    if isinstance(value, dict):
        return "{" + ", ".join("%s: %s" % (_literal(k), _literal(v)) for k, v in value.items()) + "}"
    raise AssertionError("constant patch: cannot write %r" % (value,))


def _dict_entries(node, key):
    found = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Dict):
            for k, v in zip(sub.keys, sub.values):
                if isinstance(k, ast.Constant) and k.value == key:
                    found.append(v)
                elif isinstance(k, ast.Tuple) and any(isinstance(e, ast.Constant) and e.value == key for e in k.elts):
                    found.append(v)
    return found


def _map_strings(value, change, keys=False):
    if isinstance(value, str):
        return change(value)
    if isinstance(value, list):
        return [_map_strings(v, change, keys) for v in value]
    if isinstance(value, tuple):
        return tuple(_map_strings(v, change, keys) for v in value)
    if isinstance(value, (set, frozenset)):
        return type(value)(_map_strings(v, change, keys) for v in value)
    if isinstance(value, dict):
        return {(_map_strings(k, change, keys) if keys else k): _map_strings(v, change, keys) for k, v in value.items()}
    return value


def replace_where(predicate, new, count="one"):
    def transform(value):
        for keys in (False, True):
            hits = []

            def change(text):
                if predicate(text):
                    hits.append(text)
                    return new
                return text

            out = _map_strings(value, change, keys)
            if hits:
                break
        assert hits, "constant patch: no matching string"
        assert count == "all" or len(hits) == 1, "constant patch: %d matching strings" % len(hits)
        return out
    return transform


def replace_str(old, new, count="one"):
    return replace_where(lambda text: text == old, new, count)


def append_item(item):
    def transform(value):
        assert isinstance(value, (list, tuple)), "constant patch: not a sequence: %r" % (value,)
        return value + type(value)([item])
    return transform


def patch_constant(tree_: Tree, name: str, key, transform) -> None:
    """Rewrite constant `name` (or its entry `key`) in the copy's checker, at the exact source span of that value."""
    src = tree_.read(CHECKER)
    module = ast.parse(src)
    value = _top_value(module, name)
    target = value if key is None else _one(_dict_entries(value, key), "%s entry %r" % (name, key))
    start, end = _segment(src, target)
    try:
        new_text = _literal(transform(_eval(target, module)))
    except _NotLiteral:
        # Fallback: replace matching string constants inside the target's own source text.
        hits = [n for n in ast.walk(target) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        probe = transform([n.value for n in hits])
        changed = [(n, v) for n, v in zip(hits, probe) if n.value != v]
        assert changed, "constant patch: %s could not be rewritten" % name
        out = src
        for node, new_value in sorted(changed, key=lambda pair: _segment(src, pair[0]), reverse=True):
            a, b = _segment(src, node)
            out = out[:a] + json.dumps(new_value) + out[b:]
        ast.parse(out)
        tree_.write(CHECKER, out)
        return
    out = src[:start] + new_text + src[end:]
    ast.parse(out)
    assert out != src, "constant patch: %s unchanged" % name
    tree_.write(CHECKER, out)


# ------------------------------------------------------------------------------------- scratch catalogs and texts

def _record(text: str, header: str):
    lines = text.splitlines(keepends=True)
    i = _one((k for k, line in enumerate(lines) if line.rstrip("\n") == header), "record line %r" % header)
    indent = len(header) - len(header.lstrip(" "))
    j = i + 1
    while j < len(lines):
        line = lines[j]
        if line.strip() and len(line) - len(line.lstrip(" ")) <= indent:
            break
        j += 1
    return lines, i, j


def yaml_field(text: str, header: str, field: str, new_line: str) -> str:
    lines, i, j = _record(text, header)
    k = _one((k for k in range(i + 1, j) if lines[k].lstrip(" ").startswith(field + ":")), "field " + field)
    indent = lines[k][:len(lines[k]) - len(lines[k].lstrip(" "))]
    lines[k] = indent + new_line + "\n"
    return "".join(lines)


def yaml_drop_line(text: str, header: str, needle: str) -> str:
    lines, i, j = _record(text, header)
    k = _one((k for k in range(i + 1, j) if needle in lines[k]), "line with %r" % needle)
    del lines[k]
    return "".join(lines)


def yaml_sub(text: str, header: str, old: str, new: str) -> str:
    lines, i, j = _record(text, header)
    k = _one((k for k in range(i + 1, j) if old in lines[k]), "line with %r" % old)
    lines[k] = lines[k].replace(old, new, 1)
    return "".join(lines)


def exact_sub(text: str, old: str, new: str) -> str:
    assert text.count(old) == 1, "exact string occurs %d times" % text.count(old)
    return text.replace(old, new, 1)


def _repin(data: dict, rel: str, digest: str) -> None:
    catalogues = data["catalogues"]
    hits = 0
    if isinstance(catalogues, dict):
        if isinstance(catalogues.get(rel), str):
            catalogues[rel] = digest
            hits += 1
    else:
        for item in catalogues:
            if isinstance(item, dict) and rel in item.values():
                for key, value in list(item.items()):
                    if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value):
                        item[key] = digest
                        hits += 1
    assert hits == 1, "catalogues pin for %s not found" % rel


def scratch_catalog(tree_: Tree, rel: str, edit) -> tuple:
    """Edit a catalog in the copy and re-pin its `catalogues` digest, so R2 passes. Returns (old, new) digests."""
    old = tree_.digest(rel)
    tree_.write(rel, edit(tree_.read(rel)))
    new = tree_.digest(rel)
    assert new != old
    tree_.edit_data(lambda d: _repin(d, rel, new))
    return old, new


def _sync_adr_digest(tree_: Tree, old: str, new: str) -> None:
    text = tree_.read(ADR10)
    if old in text:
        text = text.replace(old, new)
    else:
        for size in (16, 12, 10, 8):
            if old[:size] in text:
                text = text.replace(old[:size], new[:size])
                break
    tree_.write(ADR10, text)


def _temporal_record(selection: str):
    def edit(text):
        lines, i, j = _record(text, "  - id: provider.planeon.ollama")
        block = "".join(lines[i:j])
        block = block.replace("  - id: provider.planeon.ollama\n", "  - id: provider.temporal\n", 1)
        block = yaml_field(block, "  - id: provider.temporal", "harness", "harness: execution.orchestration")
        block = yaml_field(block, "  - id: provider.temporal", "selection", "selection: " + selection)
        block = yaml_field(block, "  - id: provider.temporal", "providers", "providers: [temporal]")
        if not block.endswith("\n\n"):
            block += "\n"
        return "".join(lines[:i]) + block + "".join(lines[i:])
    return edit


def _drift_cell(text: str, begin: str, end: str) -> str:
    a = text.index(begin)
    b = text.index(end, a)
    lines = text[a:b].split("\n")
    sep = _one((k for k, line in enumerate(lines) if re.match(r"\|\s*:?-{3}", line)), "table separator")
    assert lines[sep + 1].startswith("| ")
    lines[sep + 1] = lines[sep + 1].replace("| ", "| x", 1)
    return text[:a] + "\n".join(lines) + text[b:]


def _in_block(text: str, begin: str, end: str, old: str, new: str) -> str:
    a = text.index(begin)
    b = text.index(end, a)
    block = text[a:b]
    assert old in block, "%r not between %s and %s" % (old, begin, end)
    return text[:a] + block.replace(old, new, 1) + text[b:]


def _r08(tree_: Tree):
    lines = tree_.lines(P08)
    i = _one((k for k, line in enumerate(lines) if line.startswith(DURABLE)), "durable-executor bullet")
    assert lines[i + 1].startswith(SANDBOX)
    assert _enclosing(lines, i) == TOOLCHAIN_HEADING
    h = min(k for k, _ in _headings(lines) if k > i)
    assert i + 2 < h
    return lines, i, h


def _edited(line: str) -> str:
    return line.rstrip("\n") + " Edited by the oracle.\n"


# ======================================================================================================= H3, first

_NLINK_BEFORE: dict = {}


def _scripts_nlinks() -> dict:
    names = sorted(n for n in os.listdir(ROOT / "scripts") if n.endswith(".py") and not _skipped(n))
    return {n: os.lstat(ROOT / "scripts" / n).st_nlink for n in names}


def test_h3_scripts_have_one_link_before_the_run():
    _NLINK_BEFORE.update(_scripts_nlinks())
    assert _NLINK_BEFORE and set(_NLINK_BEFORE.values()) == {1}


def test_h3_no_copied_file_shares_an_inode_with_its_source(tree):
    count = 0
    for current, dirs, names in os.walk(tree.root):
        dirs[:] = [d for d in dirs if not _skipped(d)]
        for name in names:
            copied = Path(current) / name
            rel = copied.relative_to(tree.root)
            source = ROOT / rel
            a, b = os.lstat(copied), os.lstat(source)
            assert not os.path.islink(copied)
            assert (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino), str(rel)
            assert a.st_nlink == 1, str(rel)
            count += 1
    assert count >= len(COPY_FILES) + 16 + 13


# ================================================================================================ the positive

def test_the_pristine_copy_is_accepted(tree):
    _expect(tree, "accepted")


def test_the_oracle_rewrite_of_the_record_is_accepted(tree):
    tree.edit_data(lambda d: None)
    _expect(tree, "accepted")


# ===================================================================================== the design's fixed facts

def _data():
    return json.loads(_read(ROOT / DATA))


def _root_reader(rel):
    return _read(ROOT / rel)


def test_fact_schema_and_top_level_members():
    data = _data()
    assert data["schemaVersion"] == SCHEMA_V2
    assert set(data) == TOP_MEMBERS


def test_fact_counts():
    data = _data()
    assert len(data["repositories"]) == 13
    assert len(data["deployables"]) == 28
    assert sorted(r["id"] for r in data["deployables"]) == sorted(APPENDIX_A)
    assert len(data["outsideCatalogue"]) == 5
    native = [r["id"] for r in data["outsideCatalogue"] if "runtime" in r]
    assert sorted(native) == sorted(NATIVE_ROWS)


def test_fact_three_catalogues_in_order():
    catalogues = _data()["catalogues"]
    if isinstance(catalogues, dict):
        paths = list(catalogues)
    else:
        paths = [next(v for v in item.values() if isinstance(v, str) and v.startswith("architecture/"))
                 for item in catalogues]
    assert paths == CATALOGUES_ORDER


def test_fact_112_spans_with_their_parts():
    data = _data()
    spans = list(_walk_spans(data))
    assert len(spans) == SPAN_TOTAL
    frameworks = sum(len(r["frameworksSources"]) for r in data["deployables"])
    assert frameworks == 29
    harness = sum(1 for e in data["baselineBindings"] for key in ("document", "delivery") if set(e[key]) == SPAN_MEMBERS)
    assert harness == 32
    plan = [r for e in data["baselineBindings"] for r in e["rows"] if r["kind"] == PL]
    assert len(plan) == 1 and set(plan[0]["target"]["span"]) == SPAN_MEMBERS
    assert set(data["h10Sources"]["r08"]) == SPAN_MEMBERS


def test_fact_every_span_has_a_heading_section():
    spans = list(_walk_spans(_data()))
    assert len(spans) == SPAN_TOTAL
    for span in spans:
        assert isinstance(span["section"], str) and HEADING.match(span["section"]), span


def test_fact_every_span_is_located_in_its_own_section():
    """Section 3, R5 'Today's data': each enclosing heading is unique, each block matches once inside its section."""
    data = _data()
    problems = []
    spans = list(_walk_spans(data))
    assert len(spans) == SPAN_TOTAL
    for span in spans:
        where = _locate(_root_reader, span)
        if not isinstance(where, int):
            problems.append((span["path"], _pair(span), where))
        else:
            lines = _split(_root_reader(span["path"]))
            if _enclosing(lines, where) != span["section"]:
                problems.append((span["path"], _pair(span), "located under another heading"))
    assert not problems, problems


def test_fact_v1_spans_are_located_by_enclosing_heading():
    """The design's census claim for v1's 49 spans, computed without the section member (holds on v1 data too)."""
    data = _data()
    v1 = []
    for row in data["repositories"]:
        v1.extend(row["sources"])
    for row in data["deployables"]:
        v1.append(row["source"])
    for row in data["outsideCatalogue"]:
        v1.extend(row["sources"])
    assert len(v1) == 49
    problems = []
    for span in v1:
        bare = {k: v for k, v in span.items() if k != "section"}
        where = _locate(_root_reader, bare)
        if not isinstance(where, int):
            problems.append((span["path"], _pair(span), where))
    assert not problems, problems


def test_fact_r00_block_sits_at_1252():
    span = repo(_data(), "harness-engineering")["sources"][0]
    text, line = _block_text(_root_reader, span)
    assert line == R00_LINE
    assert span["section"] == R00_SECTION


def test_fact_span_roots_by_kind():
    data = _data()
    v1 = [s for r in data["repositories"] for s in r["sources"]] + [r["source"] for r in data["deployables"]]
    v1 += [s for r in data["outsideCatalogue"] for s in r["sources"]]
    assert all(s["path"].startswith(("docs/repositories/", "docs/alpha-2/")) for s in v1)
    frameworks = [s for r in data["deployables"] for s in r["frameworksSources"]]
    plan = [r["target"]["span"] for e in data["baselineBindings"] for r in e["rows"] if r["kind"] == PL]
    assert all(s["path"].startswith("docs/repositories/") for s in frameworks + plan + [data["h10Sources"]["r08"]])
    for e in data["baselineBindings"]:
        assert e["document"]["path"] == "docs/harnesses/%s.md" % e["harness"]
        assert e["delivery"]["path"] == "docs/harnesses/%s.md" % e["harness"]


def test_fact_deployable_members():
    for row in _data()["deployables"]:
        assert set(row) == DEPLOYABLE_MEMBERS, row["id"]


def test_fact_outside_rows():
    data = _data()
    for ident in NATIVE_ROWS:
        row = outside(data, ident)
        assert set(row) == NATIVE_MEMBERS, ident
        assert row["plannedLanguage"] == "RUST"
        assert {k: row[k] for k in NATIVE_VALUES} == NATIVE_VALUES
    for ident in OTHER_OUTSIDE_ROWS:
        assert set(outside(data, ident)) == OUTSIDE_V1_MEMBERS, ident


def test_fact_repository_members_unchanged():
    for row in _data()["repositories"]:
        assert set(row) == REPOSITORY_MEMBERS, row["id"]


@pytest.mark.parametrize("ident", list(APPENDIX_A))
def test_appendix_a_row(ident):
    runtime, frameworks, sources, packaging, upstream, status, decision = APPENDIX_A[ident]
    row = dep(_data(), ident)
    assert row["runtime"] == runtime
    assert row["frameworks"] == frameworks
    assert row["packaging"] == packaging
    assert row["upstream"] == upstream
    assert row["implementationStatus"] == status
    assert row["decision"] == decision
    if runtime is not None:
        assert row["runtime"] == row["toolchain"]
    else:
        assert row["plannedLanguage"] == "UPSTREAM_OWN"
    located = []
    texts = []
    for span in row["frameworksSources"]:
        assert span["section"] == TOOLCHAIN_HEADING
        text, line = _block_text(_root_reader, span)
        located.append((span["path"], line))
        texts.append(text)
    assert located == sources
    for item in frameworks:
        assert any(_whole_word(item, text) for text in texts), item
        assert item != runtime
    assert len(set(frameworks)) == len(frameworks)


def test_fact_toolchain_prefix_form():
    data = _data()
    strings = [r["toolchain"] for r in data["repositories"]]
    strings += [r["toolchain"] for r in data["deployables"] if r["plannedLanguage"] != "UPSTREAM_OWN"]
    assert len(strings) == 40
    assert all(re.match(r"\S+ \d", s) for s in strings), strings


def _flattened(data):
    return [(e["harness"], _bare(r["baseline"]), r["kind"], r["target"]) for e in data["baselineBindings"]
            for r in e["rows"]]


def test_appendix_b_bindings():
    data = _data()
    assert [e["harness"] for e in data["baselineBindings"]] == STEMS
    rows = _flattened(data)
    assert len(rows) == 31
    counts = {}
    for _, _, kind, _ in rows:
        counts[kind] = counts.get(kind, 0) + 1
    assert counts == KIND_COUNTS
    for got, want in zip(rows, APPENDIX_B):
        harness, baseline, kind, target = want
        assert got[:3] == (harness, baseline, kind)
        if kind == PL:
            path, line, token = target["span"]
            assert set(got[3]) == {"span"}
            span = got[3]["span"]
            text, located = _block_text(_root_reader, span)
            assert (span["path"], located, span["section"]) == (path, line, TOOLCHAIN_HEADING)
            assert _whole_word(token, text)
        else:
            assert got[3] == target, got
    for e in data["baselineBindings"]:
        assert set(e) == {"harness", "document", "delivery", "rows"}
        for r in e["rows"]:
            assert set(r) - {"divergence"} == {"baseline", "kind", "target"}


def test_fact_binding_sources_agree():
    data = _data()
    for e in data["baselineBindings"]:
        document, _ = _block_text(_root_reader, e["document"])
        assert re.findall(r"`([^`]+)`", document) == [_bare(r["baseline"]) for r in e["rows"]], e["harness"]
        delivery, _ = _block_text(_root_reader, e["delivery"])
        for r in e["rows"]:
            if r["kind"] == DF:
                assert "`%s`" % r["target"]["item"] in delivery, (e["harness"], r["target"])
    assert [_bare(r["baseline"]) for r in entry(data, "execution.orchestration")["rows"]][0] == \
        "planeon.orchestrator.postgres"


def test_fact_the_one_divergence():
    data = _data()
    holders = divergence_rows(data)
    assert len(holders) == 1
    harness, row = holders[0]
    assert (harness, _bare(row["baseline"])) == DIVERGENCE_HOLDER
    assert row["divergence"] == DIVERGENCE
    delivery, _ = _block_text(_root_reader, entry(data, harness)["delivery"])
    assert DIVERGENCE["deferral"] in delivery


AMENDMENT_HEADING = "## Amendment 1 (MET-GOV-005, 2026-10-26): the technology record"
AMENDMENT_TABLES = ("technology-table", "native-table", "bindings-table")


def _digest_named(text: str, digest: str) -> bool:
    return digest in text or digest[:8] in text


def test_fact_adr_amendment_and_its_captions():
    """Section 4 and section 3 R8: the appended section, its three marker pairs, one policy block, and captions that
    name the record and providers.yaml's digest only."""
    text = _read(ROOT / ADR10)
    assert text.count(AMENDMENT_HEADING + "\n") == 1
    after = text.split(AMENDMENT_HEADING + "\n", 1)[1]
    assert text.count("<!-- language-policy:begin -->") == 1 and "language-policy:" not in after
    providers = hashlib.sha256((ROOT / PROVIDERS).read_bytes()).hexdigest()
    services = hashlib.sha256((ROOT / SERVICES).read_bytes()).hexdigest()
    repositories = hashlib.sha256((ROOT / REPOSITORIES).read_bytes()).hexdigest()
    for name in AMENDMENT_TABLES:
        begin, end = "<!-- %s:begin -->" % name, "<!-- %s:end -->" % name
        assert after.count(begin) == 1 and after.count(end) == 1, name
        block = after[after.index(begin):after.index(end)]
        assert "architecture/language-placement.json" in block, name
        assert _digest_named(block, providers), name
        assert not _digest_named(block, services) and not _digest_named(block, repositories), name


def test_fact_h10_sources():
    data = _data()
    assert set(data["h10Sources"]) == {"r08"}
    span = data["h10Sources"]["r08"]
    assert span["evidence"] == H10_EVIDENCE
    text, line = _block_text(_root_reader, span)
    assert (span["path"], line, span["section"]) == (P08, 103, TOOLCHAIN_HEADING)
    assert text.startswith(DURABLE)


# ============================================================================= section 5: one test per refusal row

ROWS: dict = {}


def row(number, expected):
    def register(function):
        ROWS[number] = (expected, function)
        return function
    return register


@row(1, "R1")
def _mut01(t):
    t.edit_data(lambda d: dep(d, "operator")["frameworksSources"][0].__setitem__("section", "Deployables"))


@row(2, "R1")
def _mut02(t):
    t.edit_data(lambda d: dep(d, "operator").__setitem__("packaging", ["RPM"]))


@row(3, "R1")
def _mut03(t):
    t.edit_data(lambda d: dep(d, "operator").__setitem__("decision", "ADR-9999"))


@row(4, "R1")
def _mut04(t):
    def change(d):
        holder = divergence_rows(d)[0][1]
        holder["divergence"] = {("selected" if k == "roadmapSelection" else k): v
                                for k, v in holder["divergence"].items()}
    t.edit_data(change)


@row(5, "R1")
def _mut05(t):
    def change(d):
        target = next(r for e in d["baselineBindings"] for r in e["rows"] if r["kind"] == CM)["target"]
        del target["token"]
    t.edit_data(change)


@row(6, "R1")
def _mut06(t):
    def change(d):
        e = next(e for e in d["baselineBindings"] if any(r["kind"] == DF for r in e["rows"]))
        target = next(r for r in e["rows"] if r["kind"] == DF)["target"]
        target["span"] = copy.deepcopy(e["delivery"])
    t.edit_data(change)


@row(7, "R4")
def _mut07(t):
    old = dep(t.data(), "control-web")["toolchain"]
    patch_constant(t, "TOOLCHAIN_EXPECTED", "control-web", replace_str(old, "TypeScript"))
    t.edit_data(lambda d: dep(d, "control-web").__setitem__("toolchain", "TypeScript"))


@row(8, "R4")
def _mut08(t):
    t.edit_data(lambda d: dep(d, "operator").__setitem__("toolchain", "Go 1.26.8"))


@row(9, "R5")
def _mut09(t):
    lines = t.lines(ADR10)
    index = None
    for k, line in enumerate(lines):
        if "Rust" in line and not HEADING.match(line) and len(_matches(lines, _sha(lines, k, 1), 1)) == 1:
            head = _enclosing(lines, k)
            if head and _section_range(lines, head):
                index = k
                break
    assert index is not None

    def change(d):
        sources = outside(d, "r12-native-probes")["sources"]
        sources[0] = _make_span(t, ADR10, index, ["Rust"], sources[0])
    t.edit_data(change)


@row(10, "R5")
def _mut10(t):
    t.edit_data(lambda d: dep(d, "sandbox-runner")["frameworksSources"].__setitem__(0, _first_alpha2_span(d)))


@row(11, "R5")
def _mut11(t):
    t.edit_data(lambda d: entry(d, "runtime.ai-gateway").__setitem__(
        "document", copy.deepcopy(dep(d, "ai-gateway")["frameworksSources"][0])))


@row(12, "R5")
def _mut12(t):
    lines, _, _ = _r08(t)
    if not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    lines.append(TOOLCHAIN_HEADING + "\n")
    t.write_lines(P08, lines)


@row(13, "R5")
def _mut13(t):
    lines, _, _ = _r08(t)
    k = _one((k for k, line in enumerate(lines) if line.rstrip("\n") == TOOLCHAIN_HEADING), "toolchain heading")
    lines[k] = TOOLCHAIN_HEADING + "s\n"
    t.write_lines(P08, lines)


@row(14, "R5")
def _mut14(t):
    lines, i, h = _r08(t)
    block = lines[i]
    lines[i] = _edited(block)
    lines.insert(h + 1, block)
    t.write_lines(P08, lines)


@row(15, "R5")
def _mut15(t):
    lines, i, h = _r08(t)
    block = lines.pop(i)
    lines.insert(h, block)  # just after the next heading, which moved up by one
    t.write_lines(P08, lines)


@row(16, "R5")
def _mut16(t):
    lines, i, _ = _r08(t)
    assert _headings(lines)[-1][1] != TOOLCHAIN_HEADING and len(_headings(lines)) > 2
    block = lines.pop(i)
    if not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    lines.append(block)
    t.write_lines(P08, lines)


@row(17, "R5")
def _mut17(t):
    lines, i, _ = _r08(t)
    lines.insert(i + 2, lines[i])
    t.write_lines(P08, lines)


@row(18, "accepted")
def _mut18(t):
    lines, i, _ = _r08(t)
    lines[i], lines[i + 1] = lines[i + 1], lines[i]
    t.write_lines(P08, lines)


@row(19, "R9")
def _mut19(t):
    t.edit_data(lambda d: dep(d, "policy-decision").__setitem__("runtime", "Python 3.12.15"))


@row(20, "R10")
def _mut20(t):
    scratch_catalog(t, PROVIDERS, lambda s: yaml_drop_line(s, "  - id: module.runtime.infrastructure.operator",
                                                           "type: HELM_CHART"))


@row(21, "R10")
def _mut21(t):
    scratch_catalog(t, PROVIDERS, lambda s: yaml_sub(s, "  - id: module.trust.observability.otel-collector",
                                                     "artifact: otel/opentelemetry-collector-contrib,",
                                                     "artifact: mas-harness-trust-plane/otel-collector,"))


@row(22, "R10")
def _mut22(t):
    scratch_catalog(t, SERVICES, lambda s: yaml_field(s, "  - id: operator", "implementationStatus",
                                                      "implementationStatus: IMPLEMENTED"))


@row(23, "R10")
def _mut23(t):
    scratch_catalog(t, SERVICES, lambda s: yaml_field(s, "  - id: operator", "implementationStatus",
                                                      "implementationStatus: IMPLEMENTED"))
    patch_constant(t, "TECH_EXPECTED", "operator", replace_str("PLANNED", "IMPLEMENTED"))
    t.edit_data(lambda d: dep(d, "operator").__setitem__("implementationStatus", "IMPLEMENTED"))


@row(24, "R10")
def _mut24(t):
    scratch_catalog(t, PROVIDERS, lambda s: exact_sub(
        s, "- serviceId: operator\n  moduleId: module.runtime.infrastructure.operator\n",
        "- serviceId: operator\n  moduleId: module.runtime.infrastructure.bundle-verifier\n"))


@row(25, "R11")
def _mut25(t):
    t.edit_data(lambda d: dep(d, "policy-decision")["frameworks"].append("Django"))


@row(26, "R11")
def _mut26(t):
    patch_constant(t, "FRAMEWORKS_EXPECTED", "policy-decision", replace_str("Pydantic v2", "Py"))

    def change(d):
        items = dep(d, "policy-decision")["frameworks"]
        items[items.index("Pydantic v2")] = "Py"
    t.edit_data(change)


@row(27, "R11")
def _mut27(t):
    runtime = dep(t.data(), "policy-decision")["runtime"]
    patch_constant(t, "FRAMEWORKS_EXPECTED", "policy-decision", append_item(runtime))
    t.edit_data(lambda d: dep(d, "policy-decision")["frameworks"].append(runtime))


@row(28, "R11")
def _mut28(t):
    first = dep(t.data(), "policy-decision")["frameworks"][0]
    patch_constant(t, "FRAMEWORKS_EXPECTED", "policy-decision", append_item(first))
    t.edit_data(lambda d: dep(d, "policy-decision")["frameworks"].append(first))


@row(29, "R11")
def _mut29(t):
    lines, _, h = _r08(t)
    bounds = _section_range(lines, lines[h].rstrip("\n"))
    assert bounds is not None
    index = next(k for k in range(*bounds) if lines[k].startswith("- ")
                 and len(_matches(lines, _sha(lines, k, 1), 1, *bounds)) == 1)

    def change(d):
        sources = dep(d, "sandbox-runner")["frameworksSources"]
        assert sources[0]["path"] == P08
        sources[0] = _make_span(t, P08, index, [lines[index].rstrip("\n")], sources[0])
    t.edit_data(change)


@row(30, "R11")
def _mut30(t):
    t.edit_data(lambda d: dep(d, "sandbox-runner").__setitem__("frameworksSources", []))


@row(31, "R11")
def _mut31(t):
    t.edit_data(lambda d: outside(d, "native-host-enforcement-roles").__setitem__("frameworks", ["musl"]))


@row(32, "R12")
def _mut32(t):
    t.edit_data(lambda d: entry(d, "runtime.model-inference")["rows"].pop())


@row(33, "R12")
def _mut33(t):
    def change(d):
        rows = entry(d, "runtime.model-inference")["rows"]
        rows.insert(1, copy.deepcopy(rows[0]))
    t.edit_data(change)


@row(34, "R12")
def _mut34(t):
    def change(d):
        r = brow(d, "runtime.model-inference", "ollama/ollama")
        r["kind"] = DF
        r["target"] = {"item": "MODEL-ADOPT-001"}
    t.edit_data(change)


@row(35, "R12")
def _mut35(t):
    t.edit_data(lambda d: brow(d, "runtime.model-inference", "ollama/ollama")["target"].__setitem__(
        "record", "provider.planeon.vllm"))


@row(36, "R12")
def _mut36(t):
    scratch_catalog(t, PROVIDERS, lambda s: yaml_field(s, "  - id: provider.planeon.ollama", "providers",
                                                       "providers: []"))


@row(37, "R12")
def _mut37(t):
    scratch_catalog(t, PROVIDERS, lambda s: yaml_field(s, "  - id: provider.planeon.litellm-local", "selection",
                                                       "selection: CONDITIONAL"))


@row(38, "R12")
def _mut38(t):
    patch_constant(t, "PLAN_TOKENS", None,
                   replace_where(lambda s: s.lower().startswith("helm") and "/" not in s, "Helm 5"))


@row(39, "R12")
def _mut39(t):
    patch_constant(t, "BINDINGS_EXPECTED", None, replace_str("KN-DATA-ADOPT-001", "KN-DATA-ADOPT-002", "all"))

    def change(d):
        hits = 0
        for e in d["baselineBindings"]:
            for r in e["rows"]:
                if r["kind"] == DF and r["target"].get("item") == "KN-DATA-ADOPT-001":
                    r["target"]["item"] = "KN-DATA-ADOPT-002"
                    hits += 1
        assert hits == 3
    t.edit_data(change)


@row(40, "R12")
def _mut40(t):
    def change(d):
        b = d["baselineBindings"]
        b[0], b[1] = b[1], b[0]
    t.edit_data(change)


@row(41, "R12")
def _mut41(t):
    def change(d):
        e = entry(d, "runtime.ai-gateway")
        e["document"] = copy.deepcopy(e["delivery"])
    t.edit_data(change)


@row(42, "R12")
def _mut42(t):
    t.edit_data(lambda d: entry(d, "runtime.ai-gateway").__setitem__(
        "delivery", copy.deepcopy(entry(d, "runtime.experience")["delivery"])))


@row(43, "R12")
def _mut43(t):
    t.edit_data(lambda d: divergence_rows(d)[0][1]["divergence"].__setitem__("roadmapSelection", "LiteLLM"))


@row(44, "R12")
def _mut44(t):
    t.edit_data(lambda d: divergence_rows(d)[0][1].pop("divergence"))


@row(45, "R12")
def _mut45(t):
    def change(d):
        brow(d, "runtime.model-inference", "ollama/ollama")["divergence"] = copy.deepcopy(
            divergence_rows(d)[0][1]["divergence"])
    t.edit_data(change)


@row(46, "R12")
def _mut46(t):
    patch_constant(t, "DIVERGENCE_EXPECTED", None, replace_str("RUN-GATEWAY-ADOPT-001", "RUN-UI-ADOPT-001"))
    t.edit_data(lambda d: divergence_rows(d)[0][1]["divergence"].__setitem__("deferral", "RUN-UI-ADOPT-001"))


@row(47, "R13")
def _mut47(t):
    scratch_catalog(t, PROVIDERS, _temporal_record("DEFAULT"))


@row(48, "accepted")
def _mut48(t):
    old, new = scratch_catalog(t, PROVIDERS, _temporal_record("OPTIONAL"))
    _sync_adr_digest(t, old, new)  # the amendment captions name providers.yaml's digest (section 3, R8)


@row(49, "R13")
def _mut49(t):
    patch_constant(t, "H10_R08_EVIDENCE", None, append_item("Temporal is the default"))


@row(50, "R13")
def _mut50(t):
    scratch_catalog(t, PROVIDERS, lambda s: yaml_field(s, "  - id: provider.planeon.ollama", "selection",
                                                       "selection: DEFAULT"))


@row(51, "R13")
def _mut51(t):
    head = "- capability: planeon.otel\n  resolution: ALL\n  modules:\n  - module.trust.observability.otel-collector\n"
    scratch_catalog(t, PROVIDERS, lambda s: exact_sub(s, head, head + "  - external.otel-backend\n"))


@row(54, "R8")
def _mut54(t):
    t.write(ADR10, _drift_cell(t.read(ADR10), "<!-- technology-table:begin -->", "<!-- technology-table:end -->"))


@row(55, "R8")
def _mut55(t):
    t.write(ADR10, _drift_cell(t.read(ADR10), "<!-- language-placement:deployables:begin -->",
                               "<!-- language-placement:deployables:end -->"))


@pytest.mark.parametrize("number", sorted(ROWS), ids=lambda n: "row-%02d-%s" % (n, ROWS[n][0]))
def test_section5_row(number, tree):
    expected, mutate = ROWS[number]
    mutate(tree)
    _expect(tree, expected)


# ------------------------------------------------------------------------------- rows 52-53: R14, called directly

def _load_checker(t: Tree):
    path = t.path(CHECKER)
    name = "lp_oracle_r14_subject"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    saved_path, saved_flag = list(sys.path), sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    sys.path[:0] = [str(path.parent), str(t.root)]
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = saved_path
        sys.dont_write_bytecode = saved_flag
    return name, module


def _rule_of(exc):
    rule = getattr(exc, "rule", None)
    if isinstance(rule, str):
        return rule
    match = re.match(r"(R\d+)\b", str(exc))
    return match.group(1) if match else None


def _forms(data, row_value):
    deployables = [row_value if r.get("id") == row_value["id"] else r for r in data["deployables"]]
    whole = dict(data)
    whole["deployables"] = deployables
    return {"data": (whole,), "deployables": (deployables,), "row": (row_value,)}


def _direct_r14(t: Tree, change):
    name, module = _load_checker(t)
    try:
        function = module._r14
        params = [p for p in inspect.signature(function).parameters.values()
                  if p.default is p.empty and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
        assert len(params) == 1, "unexpected _r14 signature %s" % inspect.signature(function)
        hint = params[0].name.lower()
        order = ["data", "deployables", "row"]
        if hint in ("row", "deployable", "record", "r", "item", "entry"):
            order = ["row", "deployables", "data"]
        elif hint in ("rows", "deployables", "items", "entries"):
            order = ["deployables", "data", "row"]
        data = t.data()
        pristine = copy.deepcopy(dep(data, "otel-collector"))
        mutated = copy.deepcopy(pristine)
        change(mutated)
        tried = []
        for form in order:
            try:
                function(*_forms(copy.deepcopy(data), copy.deepcopy(pristine))[form])
            except Exception as exc:  # the pristine row must pass in this calling form
                tried.append((form, "pristine raised %r" % exc))
                continue
            try:
                function(*_forms(copy.deepcopy(data), copy.deepcopy(mutated))[form])
            except Exception as exc:
                assert _rule_of(exc) == "R14", "form %s raised %r" % (form, exc)
                return
            tried.append((form, "mutated row not refused"))
        raise AssertionError("no calling form refused the constructed row: %s" % tried)
    finally:
        sys.modules.pop(name, None)


def test_section5_row52_direct_r14_upstream_row_not_upstream_own(tree):
    _direct_r14(tree, lambda r: r.__setitem__("plannedLanguage", "PYTHON"))


def test_section5_row53_direct_r14_upstream_own_without_upstream(tree):
    _direct_r14(tree, lambda r: r.__setitem__("upstream", None))


# ===================================================== further clauses of sections 0a and 3 (beyond the 55 rows)

def test_r2_providers_edited_without_a_repin_is_r2(tree):
    tree.write(PROVIDERS, tree.read(PROVIDERS) + "\n")
    _expect(tree, "R2")


def test_r2_catalogues_out_of_order_is_r2(tree):
    def change(d):
        catalogues = d["catalogues"]
        if isinstance(catalogues, dict):
            items = list(catalogues.items())
            d["catalogues"] = dict([items[1], items[0]] + items[2:])
        else:
            catalogues[0], catalogues[1] = catalogues[1], catalogues[0]
    tree.edit_data(change)
    _expect(tree, "R2")


def test_r1_schema_v1_id_on_v2_data_is_r1(tree):
    tree.edit_data(lambda d: d.__setitem__("schemaVersion", SCHEMA_V1))
    _expect(tree, "R1")


def test_c14_h10_source_off_docs_repositories_is_r5(tree):
    tree.edit_data(lambda d: d["h10Sources"].__setitem__("r08", _first_alpha2_span(d)))
    _expect(tree, "R5")


def test_c14_plan_library_span_off_docs_repositories_is_r5(tree):
    def change(d):
        r = next(r for e in d["baselineBindings"] for r in e["rows"] if r["kind"] == PL)
        r["target"]["span"] = _first_alpha2_span(d)
    tree.edit_data(change)
    _expect(tree, "R5")


def test_br_tt_1_plan_span_lines_only_is_not_r5_or_r12(tree):
    """BR-TT-1: a PLAN span's `lines` are display-only. A rendered table may still show them (R8, last)."""
    def change(d):
        span = next(r for e in d["baselineBindings"] for r in e["rows"] if r["kind"] == PL)["target"]["span"]
        first, last = _pair(span)
        span["lines"] = _with_lines(span, first + 1, last + 1)
    tree.edit_data(change)
    outcome, output = tree.run()
    assert outcome in ("accepted", "R8"), "%s: %s" % (outcome, output[-1500:])


def test_br_tt_1_plan_span_sha256_is_refused(tree):
    def change(d):
        span = next(r for e in d["baselineBindings"] for r in e["rows"] if r["kind"] == PL)["target"]["span"]
        span["sha256"] = "0" * 64
    tree.edit_data(change)
    _expect(tree, "R5")


def test_r13_conditional_temporal_record_is_r13(tree):
    scratch_catalog(tree, PROVIDERS, _temporal_record("CONDITIONAL"))
    _expect(tree, "R13")


def test_r5_residual_same_section_copy_then_edit_is_accepted(tree):
    """MON-TT-D3 Q-D2-2': a same-section copy with the original then edited is accepted (stated residual)."""
    lines, i, _ = _r08(tree)
    lines.insert(i + 2, lines[i])
    lines[i] = _edited(lines[i])
    tree.write_lines(P08, lines)
    _expect(tree, "accepted")


def _single_heading_case(t: Tree, copy_then_edit: bool):
    data = t.data()
    span = outside(data, "native-host-enforcement-roles")["sources"][0]
    rel = span["path"]
    lines = t.lines(rel)
    assert rel.startswith("docs/alpha-2/") and len(_headings(lines)) == 1
    first, last = _pair(span)
    count = last - first + 1
    start = _one(_matches(lines, span["sha256"], count), "alpha-2 block")
    block = lines[start:start + count]
    if copy_then_edit:
        lines[start] = _edited(lines[start])
    else:
        del lines[start:start + count]
    if not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    lines.extend(block)
    t.write_lines(rel, lines)


def test_r5_residual_single_heading_file_move_to_end_is_accepted(tree):
    """TT-D2-2: in the two single-heading alpha-2 files the section is the whole file."""
    _single_heading_case(tree, copy_then_edit=False)
    _expect(tree, "accepted")


def test_r5_residual_single_heading_file_copy_then_edit_is_accepted(tree):
    _single_heading_case(tree, copy_then_edit=True)
    _expect(tree, "accepted")


def test_appendix_c_repository_toolchain_mutation_is_now_r4(tree):
    """Appendix C: v1's `repository-toolchain-not-in-span` case is refused first by v2's R4."""
    tree.edit_data(lambda d: repo(d, "contracts").__setitem__("toolchain", "Python 3.12.15"))
    _expect(tree, "R4")


def test_appendix_c_deployable_toolchain_mutation_is_now_r4(tree):
    """Appendix C: v1's `deployable-toolchain-not-in-span` case is refused first by v2's R4."""
    tree.edit_data(lambda d: dep(d, "sandbox-runner").__setitem__("toolchain", "Python 3.12.15"))
    _expect(tree, "R4")


# ================================================================= v1 behaviours that hold under v2 (section 6)

def test_v1_r1_schema_version_unknown_id_is_r1(tree):
    """Appendix C: R1's `schema-version` case moves to a v3 id, still R1."""
    tree.edit_data(lambda d: d.__setitem__("schemaVersion", SCHEMA_V3))
    _expect(tree, "R1")


def test_v1_r1_unknown_member_is_r1(tree):
    tree.edit_data(lambda d: dep(d, "operator").__setitem__("oracleExtra", "x"))
    _expect(tree, "R1")


def test_v1_r2_services_edited_without_a_repin_is_r2(tree):
    tree.write(SERVICES, tree.read(SERVICES) + "\n")
    _expect(tree, "R2")


def test_v1_r2_repositories_edited_without_a_repin_is_r2(tree):
    tree.write(REPOSITORIES, tree.read(REPOSITORIES) + "\n")
    _expect(tree, "R2")


def test_v1_r2_policy_line_changed_is_r2(tree):
    tree.write(ADR10, _in_block(tree.read(ADR10), "<!-- language-policy:begin -->", "<!-- language-policy:end -->",
                                "Python is the default language", "Python is the preferred language"))
    _expect(tree, "R2")


def test_v1_r3_deployable_owner_differs_from_the_catalog_is_r3(tree):
    tree.edit_data(lambda d: dep(d, "bundle-verifier").__setitem__("ownerRepository", "mas-harness-trust-plane"))
    _expect(tree, "R3")


def test_v1_r4_repository_languages_changed_is_r4(tree):
    tree.edit_data(lambda d: repo(d, "contracts").__setitem__("languages", ["GO"]))
    _expect(tree, "R4")


def test_v1_r4_repository_name_changed_is_r4(tree):
    tree.edit_data(lambda d: repo(d, "contracts").__setitem__("name", "mas-harness-contract"))
    _expect(tree, "R4")


def test_v1_r4_repository_number_changed_is_r4(tree):
    tree.edit_data(lambda d: repo(d, "contracts").__setitem__("rNumber", "R13"))
    _expect(tree, "R4")


def test_v1_r5_span_digest_changed_is_r5(tree):
    tree.edit_data(lambda d: repo(d, "contracts")["sources"][0].__setitem__("sha256", "0" * 64))
    _expect(tree, "R5")


def test_v1_r5_evidence_not_in_the_span_is_r5(tree):
    tree.edit_data(lambda d: repo(d, "contracts")["sources"][0].__setitem__("evidence", ["oracle evidence absent"]))
    _expect(tree, "R5")


def test_v1_r5_cited_text_changed_is_r5(tree):
    lines = tree.lines(P08)
    k = _one((k for k, line in enumerate(lines) if line.startswith(PY_BULLET)), "R08 toolchain bullet")
    lines[k] = _edited(lines[k])
    tree.write_lines(P08, lines)
    _expect(tree, "R5")


def test_v1_r5_a_shift_of_the_cited_lines_is_accepted(tree):
    tree.write(P08, "\n" + tree.read(P08))
    _expect(tree, "accepted")


def test_v1_r6_outside_row_owner_changed_is_r6(tree):
    tree.edit_data(lambda d: outside(d, "typescript-sdk").__setitem__("ownerRepository", "mas-harness-contracts"))
    _expect(tree, "R6")


def test_v1_r7_exception_default_language_changed_is_r7(tree):
    def change(d):
        row_value = _one((r for r in d["exceptions"] if r.get("deployable") == "ai-gateway"), "exception ai-gateway")
        row_value["defaultLanguage"] = "PYTHON"
    tree.edit_data(change)
    _expect(tree, "R7")


def test_v1_r8_caption_digest_drift_is_r8(tree):
    tree.write(ADR10, _in_block(tree.read(ADR10), "<!-- language-placement:deployables:begin -->",
                                "<!-- language-placement:deployables:end -->", tree.digest(SERVICES), "0" * 64))
    _expect(tree, "R8")


def test_v1_r8_repositories_table_cell_drift_is_r8(tree):
    tree.write(ADR10, _drift_cell(tree.read(ADR10), "<!-- language-placement:repositories:begin -->",
                                  "<!-- language-placement:repositories:end -->"))
    _expect(tree, "R8")


# ====================================================================================================== H3, last

def test_h3_zz_copies_removed_and_links_unchanged(temp_parent):
    assert list(temp_parent.iterdir()) == []
    after = _scripts_nlinks()
    assert set(after.values()) == {1}
    if _NLINK_BEFORE:
        assert after == _NLINK_BEFORE
