#!/usr/bin/env python3
"""Language placement v2 (MET-GOV-005, TECH-TRUTH-001; v1 MET-GOV-004, LANG-PLACEMENT-ADR-001): the checker of ADR
0010's data.

`architecture/language-placement.json` places the 13 repositories, the 28 deployables of `architecture/services.yaml`
and the rows outside that catalogue on a planned language. Each row is tied by line digest to the spans of the
repository plans (and the alpha-2 amendments) that state it. The data also lists the exceptions under the owner's
LANG-D2 (b). Schema v2 (ADR 0010 amendment 1) adds the technology record: each deployable's runtime, frameworks,
packaging, adopted upstream, implementation status and decision reference; the same values for the two native rows
outside the catalogue; the baseline bindings of the 16 harness documents; and R08's H10 executor line.
`docs/adr/0010-language-placement.md` carries the policy text, LANG-D2 (a), the four tables and the amendment's three
tables this checker renders. Every enum and every expected value is a constant below (binding build rules BR-GOV4-1
and BR-TT-1 to BR-TT-4), so the data carries no list of its own. The ADR decides no deployable's language beyond what
the plans state.

Rules, in the order R1-R7, R9-R14, then R8; the first rule broken is reported with its id:
  R1 shape: closed objects and member types; every enum value is in its constant; the parse rules of `strict()`;
     every span's `section` is a Markdown heading line; each binding target has its kind's closed shape.
  R2 catalogues and policy: services.yaml, repositories.yaml and providers.yaml, in that order, each with the head
     bytes' sha256; services.yaml's ids are unique and as many as its counts.total; repositories.yaml's ids are unique
     and 13; providers.yaml lists modules with unique ids and service bindings with unique service ids; policySha256
     and the ADR's policy line are POLICY_SHA256.
  R3 deployables: exactly services.yaml's ids, each once; ownerRepository and kind as catalogued; (status, plane,
     planeSource, plannedLanguage) equal EXPECTED[id].
  R4 repositories and toolchains: exactly repositories.yaml's ids and names; the plan docs/repositories/NN-<lowercased
     name>.md gives rNumber RNN and the first span's path; languages equal REPO_LANGUAGES[id]; every toolchain string
     equals TOOLCHAIN_EXPECTED's, and a non-UPSTREAM_OWN one begins with the "Name version" form (C1-3).
  R5 sources: every span sits under its kind's roots (C1-4) and is located in its section (C2-2): its `section` occurs
     once in its file as a heading line, and exactly one block of last - first + 1 whole lines between that heading and
     the next heading line has the span's sha256 and carries its evidence (`lines` are display-only: a move within the
     section is accepted); a deployable's evidence holds its id token and its language token; a repository's spans
     carry each of its languages' tokens; every toolchain string occurs verbatim in one of its row's located spans.
  R6 outside the catalogue: exactly OUTSIDE_EXPECTED's ids, each with its (ownerRepository, plannedLanguage), whose
     spans carry its language token.
  R7 exceptions: one row per PENDING_HOTPATH_DECISION or CONTROL_LOOP_TO_BE_CONFIRMED deployable and none otherwise,
     owned by the deployable's repository and implementationOwnership packet, with GO as the default, the deployable's
     planned language, and evidence that begins PENDING: and names LANG-HOTPATH-DECISION-001 or the owning packet.
  R9 technology fields: each deployable's and native row's (runtime, packaging, upstream, implementationStatus,
     decision) equals TECH_EXPECTED[id].
  R10 catalog agreement (deployables; native rows are skipped): the module is providers.yaml's
     serviceModuleBindings[id] and ends with .<id>; packaging is its install-unit types; upstream is its single
     OCI_IMAGE artifact not under mas-harness-, or null; implementationStatus is UPSTREAM_MANAGED exactly when upstream
     is set and otherwise services.yaml's; APPROVED and IMPLEMENTED are refused (no harness-onion record states either).
  R11 frameworks: frameworks equal FRAMEWORKS_EXPECTED[id]; each item is a whole word of one of the row's located
     frameworksSources blocks, each in "## Deployables and toolchain"; no item is the runtime or repeated; every
     non-UPSTREAM_OWN deployable has a frameworks source; the native rows' frameworks are [].
  R12 baseline bindings: each entry's document and delivery spans are in docs/harnesses/<harness>.md; the entries'
     stems are STEMS, in order; the flattened rows equal BINDINGS_EXPECTED; each document span holds exactly its rows'
     upstreams as backticked tokens, in order; each catalog or optional token is in its record's providers, and the
     record's selection matches the kind; each PLAN_LIBRARY span is a toolchain bullet carrying PLAN_TOKENS[baseline]
     as a whole word; each DEFERRED item occurs backticked on the entry's Delivery line; the one divergence is
     DIVERGENCE_EXPECTED, on DIVERGENCE_ROW, and its deferral occurs backticked on that harness's Delivery line.
  R13 drift: R08's executor line carries H10_R08_EVIDENCE, and no DEFAULT or CONDITIONAL providers.yaml record names
     Temporal (O5); among a harness's bound records, none in a providerExclusivityGroup is DEFAULT, and at most one per
     capability (capabilityProviders) is DEFAULT (O4).
  R14 upstream language: a deployable with an upstream is UPSTREAM_OWN, and an UPSTREAM_OWN deployable has one.
  R8 tables: each of the ADR's four table blocks, and each of the amendment's three, equals this checker's rendering of
     the data's rows.

Usage (repository root):
  python3 scripts/language_placement.py check [--root DIR]     exit 0 accepted, 1 refused, 2 usage

The catalogues are read through scripts/safe_yaml.py (MON-LANG-2); standard library otherwise. The harness documents
are read by exact path only (the 16 closed stems); no directory beyond v1's plan listing is listed.
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
SCHEMA_VERSION = "planeon.internal.language-placement/v2"
DATA_PATH = "architecture/language-placement.json"
ADR_PATH = "docs/adr/0010-language-placement.md"
ADR11_PATH = "docs/adr/0011-h10-execution-authority.md"
SERVICES_PATH = "architecture/services.yaml"
REPOSITORIES_PATH = "architecture/repositories.yaml"
PROVIDERS_PATH = "architecture/providers.yaml"
CATALOGUES = (SERVICES_PATH, REPOSITORIES_PATH, PROVIDERS_PATH)
PLANS_DIR = "docs/repositories"
HARNESSES_DIR = "docs/harnesses"
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

# ---------------------------------------------------------------- the v2 closed constants (MET-GOV-005; BR-TT-1..4)

# The catalog's 12 install-unit types, plus NATIVE_BINARY for the native rows (TT-D1-10).
PACKAGING = ("PYTHON_WHEEL", "NPM_TARBALL", "OCI_ARTIFACT", "OCI_IMAGE", "HELM_CHART", "CLUSTER_API", "LOCAL_BINARY",
             "KUBERNETES_RUNTIME_CLASS", "EXTERNAL_ENDPOINT", "MOUNTED_VOLUME", "DATABASE_EXTENSION",
             "DATABASE_SERVICE", "NATIVE_BINARY")
IMPLEMENTATION_STATUSES = ("PLANNED", "APPROVED", "IMPLEMENTED", "UPSTREAM_MANAGED")
UPSTREAM_MANAGED = "UPSTREAM_MANAGED"
# No harness-onion record states an approved or implemented deployable at the base (R10).
UNSTATED_AT_BASE = ("APPROVED", "IMPLEMENTED")
DECISIONS = (ADR_PATH, ADR11_PATH, HOTPATH_ITEM, "KN-DATA-001")
BINDING_KINDS = ("CATALOG_MODULE", "OPTIONAL_ADAPTER", "PLAN_LIBRARY", "DEFERRED")
TARGET_MEMBERS = {"CATALOG_MODULE": ("record", "token"), "OPTIONAL_ADAPTER": ("record", "token"),
                  "PLAN_LIBRARY": ("span",), "DEFERRED": ("item",)}
# A bound record's selection, per kind (R12).
SELECTIONS = {"CATALOG_MODULE": ("DEFAULT", "CONDITIONAL"), "OPTIONAL_ADAPTER": ("OPTIONAL",)}
NATIVE_ROWS = ("native-host-enforcement-roles", "r12-native-probes")
FIRST_PARTY_PREFIX = "mas-harness-"
TOOLCHAIN_SECTION = "## Deployables and toolchain"
TEMPORAL = "temporal"
# The roots a span may cite, by span kind (C1-4).
V1_ROOTS = ("docs/repositories/", "docs/alpha-2/")
PLAN_ROOTS = ("docs/repositories/",)
HARNESS_ROOTS = ("docs/harnesses/",)

# Each row's exact toolchain string, by table (C1-3; TT-D1-8); repositories.yaml's and services.yaml's ids,
# in their catalogues' order. A non-UPSTREAM_OWN string also begins with the "Name version" form.
TOOLCHAIN_EXPECTED = {
    "repositories": {
        "harness-engineering": "Python 3.12.14",
        "contracts": "Python 3.12.14",
        "sdks": "Python 3.10-3.13 with development baseline 3.12.14",
        "industry-packs": "Python 3.12.14",
        "control-plane": "Node 24.20.0 LTS",
        "runtime-plane": "Python 3.12.14",
        "model-plane": "Python 3.12.14",
        "knowledge-plane": "Python 3.12.14",
        "execution-plane": "Python 3.12.14",
        "trust-plane": "Python 3.12.14",
        "operator": "Go 1.26.7",
        "distribution": "Python 3.12.14",
        "conformance-labs": "Python 3.12.14",
    },
    "deployables": {
        "bundle-verifier": "Go 1.26.7",
        "otel-collector": "upstream pinned images/config modules",
        "operator": "Go 1.26.7",
        "policy-decision": "Python 3.12.14",
        "sandbox-runner": "Python 3.12.14",
        "fleet-sync-agent": "Go 1.26.7",
        "guardrail-service": "Python 3.12.14",
        "usage-ledger": "Python 3.12.14",
        "governance-service": "Python 3.12.14",
        "domain-service": "Python 3.12.14",
        "registry-service": "Python 3.12.14",
        "inference-api": "Python 3.12.14",
        "connector-controller": "Python 3.12.14",
        "memory-service": "Python 3.12.14",
        "control-web": "Node 24.20.0 LTS",
        "ingest-worker": "Python 3.12.14",
        "retrieval-service": "Python 3.12.14",
        "protocol-gateway": "Python 3.12.14",
        "evidence-service": "Python 3.12.14",
        "profile-compiler-worker": "Python 3.12.14",
        "index-worker": "Python 3.12.14",
        "orchestration-api": "Python 3.12.14",
        "decision-service": "Python 3.12.14",
        "assurance-worker": "Python 3.12.14",
        "tool-broker": "Python 3.12.14",
        "orchestration-worker": "Python 3.12.14",
        "ai-gateway": "Python 3.12.14",
        "experience-gateway": "Python 3.12.14",
    },
}
# Each deployable, then each native row: (runtime, packaging, upstream, implementationStatus, decision)
# (design Appendix A).
TECH_EXPECTED = {
    "bundle-verifier": ("Go 1.26.7", ("OCI_IMAGE",), None, "PLANNED", ADR_PATH),
    "otel-collector": (None, ("HELM_CHART", "OCI_IMAGE"), "otel/opentelemetry-collector-contrib", "UPSTREAM_MANAGED",
        ADR_PATH),
    "operator": ("Go 1.26.7", ("HELM_CHART", "OCI_IMAGE"), None, "PLANNED", ADR_PATH),
    "policy-decision": ("Python 3.12.14", ("OCI_IMAGE",), None, "PLANNED", ADR_PATH),
    "sandbox-runner": ("Python 3.12.14", ("OCI_IMAGE",), None, "PLANNED", ADR_PATH),
    "fleet-sync-agent": ("Go 1.26.7", ("OCI_IMAGE",), None, "PLANNED", ADR_PATH),
    "guardrail-service": ("Python 3.12.14", ("OCI_IMAGE",), None, "PLANNED", ADR_PATH),
    "usage-ledger": ("Python 3.12.14", ("OCI_IMAGE",), None, "PLANNED", ADR_PATH),
    "governance-service": ("Python 3.12.14", ("OCI_IMAGE",), None, "PLANNED", ADR_PATH),
    "domain-service": ("Python 3.12.14", ("OCI_IMAGE",), None, "PLANNED", ADR_PATH),
    "registry-service": ("Python 3.12.14", ("OCI_IMAGE",), None, "PLANNED", ADR_PATH),
    "inference-api": ("Python 3.12.14", ("OCI_IMAGE",), None, "PLANNED", ADR_PATH),
    "connector-controller": ("Python 3.12.14", ("OCI_IMAGE",), None, "PLANNED", "KN-DATA-001"),
    "memory-service": ("Python 3.12.14", ("OCI_IMAGE",), None, "PLANNED", ADR_PATH),
    "control-web": ("Node 24.20.0 LTS", ("HELM_CHART", "OCI_IMAGE"), None, "PLANNED", ADR_PATH),
    "ingest-worker": ("Python 3.12.14", ("OCI_IMAGE",), None, "PLANNED", ADR_PATH),
    "retrieval-service": ("Python 3.12.14", ("OCI_IMAGE",), None, "PLANNED", ADR_PATH),
    "protocol-gateway": ("Python 3.12.14", ("OCI_IMAGE",), None, "PLANNED", HOTPATH_ITEM),
    "evidence-service": ("Python 3.12.14", ("OCI_IMAGE",), None, "PLANNED", ADR_PATH),
    "profile-compiler-worker": ("Python 3.12.14", ("OCI_IMAGE",), None, "PLANNED", ADR_PATH),
    "index-worker": ("Python 3.12.14", ("OCI_IMAGE",), None, "PLANNED", ADR_PATH),
    "orchestration-api": ("Python 3.12.14", ("OCI_IMAGE",), None, "PLANNED", ADR11_PATH),
    "decision-service": ("Python 3.12.14", ("OCI_IMAGE",), None, "PLANNED", ADR_PATH),
    "assurance-worker": ("Python 3.12.14", ("OCI_IMAGE",), None, "PLANNED", ADR_PATH),
    "tool-broker": ("Python 3.12.14", ("OCI_IMAGE",), None, "PLANNED", HOTPATH_ITEM),
    "orchestration-worker": ("Python 3.12.14", ("OCI_IMAGE",), None, "PLANNED", ADR11_PATH),
    "ai-gateway": ("Python 3.12.14", ("OCI_IMAGE",), None, "PLANNED", HOTPATH_ITEM),
    "experience-gateway": ("Python 3.12.14", ("OCI_IMAGE",), None, "PLANNED", HOTPATH_ITEM),
    "native-host-enforcement-roles": ("Rust", ("NATIVE_BINARY",), None, "PLANNED", ADR_PATH),
    "r12-native-probes": ("Rust", ("NATIVE_BINARY",), None, "PLANNED", ADR_PATH),
}
# Each deployable's frameworks, in the order of its toolchain bullets (design Appendix A; TT-D1-6, TT-D2-6).
FRAMEWORKS_EXPECTED = {
    "bundle-verifier": ("controller-runtime", "Kubebuilder/envtest", "Helm 4.2.0", "Cosign 3.1.3", "Kustomize 5.8.1"),
    "otel-collector": (),
    "operator": ("controller-runtime", "Kubebuilder/envtest", "Helm 4.2.0", "Cosign 3.1.3", "Kustomize 5.8.1"),
    "policy-decision": ("FastAPI", "Pydantic v2", "psycopg 3", "cryptography", "HTTPX", "OpenTelemetry", "jsonschema",
        "pytest", "OPA"),
    "sandbox-runner": ("FastAPI", "Pydantic v2", "psycopg 3", "jsonschema", "cryptography", "HTTPX", "OpenTelemetry",
        "MCP SDK compatible with 2026-07-28 plus 2025-11-25", "A2A v1"),
    "fleet-sync-agent": ("controller-runtime", "Kubebuilder/envtest", "Helm 4.2.0", "Cosign 3.1.3", "Kustomize 5.8.1"),
    "guardrail-service": ("FastAPI", "Pydantic v2", "psycopg 3", "cryptography", "HTTPX", "OpenTelemetry",
        "jsonschema", "pytest"),
    "usage-ledger": ("FastAPI", "Pydantic v2", "psycopg 3", "cryptography", "HTTPX", "OpenTelemetry", "jsonschema",
        "pytest"),
    "governance-service": ("FastAPI", "Pydantic v2", "psycopg 3", "cryptography", "HTTPX", "OpenTelemetry",
        "jsonschema", "pytest"),
    "domain-service": ("FastAPI", "Pydantic v2", "psycopg 3", "PostgreSQL/pgvector", "RDFLib", "pySHACL", "jsonschema",
        "HTTPX", "cryptography", "OpenTelemetry"),
    "registry-service": ("FastAPI", "Pydantic v2", "psycopg 3", "cryptography", "HTTPX", "OpenTelemetry", "jsonschema",
        "pytest"),
    "inference-api": ("FastAPI", "Pydantic v2", "Uvicorn", "HTTPX", "cryptography", "structlog", "SSE",
        "OpenTelemetry"),
    "connector-controller": ("FastAPI", "Pydantic v2", "psycopg 3", "PostgreSQL/pgvector", "RDFLib", "pySHACL",
        "jsonschema", "HTTPX", "cryptography", "OpenTelemetry"),
    "memory-service": ("FastAPI", "Pydantic v2", "psycopg 3", "PostgreSQL/pgvector", "RDFLib", "pySHACL", "jsonschema",
        "HTTPX", "cryptography", "OpenTelemetry"),
    "control-web": ("Next.js 16.3.3 Active LTS with the App Router", "React 19.2", "TypeScript 5", "Prisma 6.19.3",
        "PostgreSQL", "AJV 8.20.0", "Vitest", "Playwright"),
    "ingest-worker": ("FastAPI", "Pydantic v2", "psycopg 3", "PostgreSQL/pgvector", "RDFLib", "pySHACL", "jsonschema",
        "HTTPX", "cryptography", "OpenTelemetry"),
    "retrieval-service": ("FastAPI", "Pydantic v2", "psycopg 3", "PostgreSQL/pgvector", "RDFLib", "pySHACL",
        "jsonschema", "HTTPX", "cryptography", "OpenTelemetry"),
    "protocol-gateway": ("FastAPI", "Pydantic v2", "psycopg 3", "jsonschema", "cryptography", "HTTPX", "OpenTelemetry",
        "MCP SDK compatible with 2026-07-28 plus 2025-11-25", "A2A v1"),
    "evidence-service": ("FastAPI", "Pydantic v2", "psycopg 3", "cryptography", "HTTPX", "OpenTelemetry", "jsonschema",
        "pytest"),
    "profile-compiler-worker": ("`uv` 0.12.7",),
    "index-worker": ("FastAPI", "Pydantic v2", "psycopg 3", "PostgreSQL/pgvector", "RDFLib", "pySHACL", "jsonschema",
        "HTTPX", "cryptography", "OpenTelemetry"),
    "orchestration-api": ("FastAPI", "Pydantic v2", "psycopg 3", "jsonschema", "cryptography", "HTTPX",
        "OpenTelemetry", "MCP SDK compatible with 2026-07-28 plus 2025-11-25", "A2A v1"),
    "decision-service": ("FastAPI", "Pydantic v2", "psycopg 3", "jsonschema", "cryptography", "HTTPX", "OpenTelemetry",
        "MCP SDK compatible with 2026-07-28 plus 2025-11-25", "A2A v1"),
    "assurance-worker": ("FastAPI", "Pydantic v2", "psycopg 3", "cryptography", "HTTPX", "OpenTelemetry", "jsonschema",
        "pytest"),
    "tool-broker": ("FastAPI", "Pydantic v2", "psycopg 3", "jsonschema", "cryptography", "HTTPX", "OpenTelemetry",
        "MCP SDK compatible with 2026-07-28 plus 2025-11-25", "A2A v1"),
    "orchestration-worker": ("FastAPI", "Pydantic v2", "psycopg 3", "jsonschema", "cryptography", "HTTPX",
        "OpenTelemetry", "MCP SDK compatible with 2026-07-28 plus 2025-11-25", "A2A v1"),
    "ai-gateway": ("FastAPI/Starlette", "Pydantic v2", "HTTPX", "psycopg 3", "cryptography", "OpenTelemetry",
        "SSE support"),
    "experience-gateway": ("FastAPI/Starlette", "Pydantic v2", "HTTPX", "psycopg 3", "cryptography", "OpenTelemetry",
        "SSE support"),
}
# The 16 closed harness stems, in order (R12; TT-D1-11).
STEMS = (
    "execution.ml-decision", "execution.orchestration", "execution.protocol-interoperability",
    "execution.tool-skill-sandbox", "knowledge.data-integration", "knowledge.domain-semantic", "knowledge.memory-state",
    "knowledge.retrieval-context", "runtime.ai-gateway", "runtime.experience", "runtime.infrastructure",
    "runtime.model-inference", "trust.evaluation-assurance", "trust.governance-agentops", "trust.observability-finops",
    "trust.security-safety",
)
# A PLAN_LIBRARY baseline's token, carried as a whole word by its toolchain bullet (R12).
PLAN_TOKENS = {"helm/helm": "Helm 4.2.0"}
# The flattened binding rows, (harness, baseline, kind, target key), in STEMS order and then line order
# (design Appendix B; TT-D1-1, TT-D1-2). A target key is (record, token), (item,), or a PLAN_LIBRARY span's
# (path, section, sha256, evidence): its `lines` are display-only (BR-TT-1).
BINDINGS_EXPECTED = (
    ("execution.ml-decision", "scikit-learn/scikit-learn", "CATALOG_MODULE",
     ("provider.execution.decision-sklearn", "planeon.sklearn")),
    ("execution.ml-decision", "microsoft/onnxruntime", "CATALOG_MODULE",
     ("provider.execution.decision-onnx", "planeon.onnx")),
    ("execution.orchestration", "planeon.orchestrator.postgres", "CATALOG_MODULE",
     ("module.execution.orchestration.orchestration-worker", "planeon.orchestrator.postgres")),
    ("execution.orchestration", "temporalio/temporal", "DEFERRED", ("EXEC-TEMPORAL-001",)),
    ("execution.protocol-interoperability", "modelcontextprotocol/python-sdk", "CATALOG_MODULE",
     ("provider.execution.protocol-mcp", "planeon.mcp")),
    ("execution.protocol-interoperability", "a2aproject/a2a-python", "CATALOG_MODULE",
     ("provider.execution.protocol-a2a", "planeon.a2a")),
    ("execution.tool-skill-sandbox", "google/gvisor", "CATALOG_MODULE",
     ("provider.execution.sandbox-gvisor", "planeon.sandbox.gvisor")),
    ("execution.tool-skill-sandbox", "bytecodealliance/wasmtime", "CATALOG_MODULE",
     ("provider.execution.sandbox-wasmtime", "planeon.sandbox.wasmtime")),
    ("knowledge.data-integration", "trinodb/trino", "DEFERRED", ("KN-DATA-ADOPT-001",)),
    ("knowledge.data-integration", "fivetran/great_expectations", "DEFERRED", ("KN-DATA-ADOPT-001",)),
    ("knowledge.data-integration", "OpenLineage/OpenLineage", "DEFERRED", ("KN-DATA-ADOPT-001",)),
    ("knowledge.domain-semantic", "RDFLib/rdflib", "CATALOG_MODULE",
     ("module.knowledge.domain-semantic.domain-service", "planeon.rdflib")),
    ("knowledge.domain-semantic", "RDFLib/pySHACL", "CATALOG_MODULE",
     ("module.knowledge.domain-semantic.domain-service", "planeon.pyshacl")),
    ("knowledge.memory-state", "mem0ai/mem0", "DEFERRED", ("KN-MEM-ADOPT-001",)),
    ("knowledge.retrieval-context", "run-llama/llama_index", "DEFERRED", ("KN-RET-ADOPT-001",)),
    ("knowledge.retrieval-context", "pgvector/pgvector", "CATALOG_MODULE", ("external.pgvector", "tenant.pgvector")),
    ("runtime.ai-gateway", "BerriAI/litellm", "OPTIONAL_ADAPTER",
     ("provider.planeon.litellm-local", "planeon.litellm-local")),
    ("runtime.experience", "ag-ui-protocol/ag-ui", "OPTIONAL_ADAPTER",
     ("provider.planeon.experience-agui", "planeon.experience.agui")),
    ("runtime.experience", "CopilotKit/CopilotKit", "DEFERRED", ("RUN-UI-ADOPT-001",)),
    ("runtime.infrastructure", "kubernetes/kubernetes", "CATALOG_MODULE",
     ("provider.runtime.infrastructure.kubernetes-upstream", "kubernetes.upstream")),
    ("runtime.infrastructure", "helm/helm", "PLAN_LIBRARY",
     ("docs/repositories/10-mas-harness-operator.md", "## Deployables and toolchain",
      "0c87e82ec386a5e786d638756e78a1a8401f0423530abf568df61f6bb6ec80b3", ("Helm 4.2.0",))),
    ("runtime.model-inference", "ollama/ollama", "CATALOG_MODULE", ("provider.planeon.ollama", "planeon.ollama")),
    ("runtime.model-inference", "ggml-org/llama.cpp", "CATALOG_MODULE",
     ("provider.planeon.llamacpp", "planeon.llamacpp")),
    ("runtime.model-inference", "vllm-project/vllm", "CATALOG_MODULE", ("provider.planeon.vllm", "planeon.vllm")),
    ("trust.evaluation-assurance", "UKGovernmentBEIS/inspect_ai", "DEFERRED", ("TRUST-EVAL-ADOPT-001",)),
    ("trust.governance-agentops", "open-policy-agent/opa", "CATALOG_MODULE", ("external.opa-engine", "opa")),
    ("trust.governance-agentops", "mlflow/mlflow", "DEFERRED", ("TRUST-GOV-ADOPT-001",)),
    ("trust.observability-finops", "open-telemetry/opentelemetry-collector", "CATALOG_MODULE",
     ("module.trust.observability.otel-collector", "planeon.otel")),
    ("trust.observability-finops", "prometheus/prometheus", "CATALOG_MODULE", ("external.otel-backend", "prometheus")),
    ("trust.security-safety", "open-policy-agent/opa", "CATALOG_MODULE", ("external.opa-engine", "opa")),
    ("trust.security-safety", "data-privacy-stack/presidio", "DEFERRED", ("TRUST-SAFE-ADOPT-001",)),
)
# The one recorded divergence (Q-TT-4; MON-TT-D2, MON-TT-DESIGN-R1): recorded, never resolved.
DIVERGENCE_ROW = ("runtime.ai-gateway", "BerriAI/litellm")
DIVERGENCE_EXPECTED = {"roadmapSelection": "Agent Router", "decisions": ("OW-D3", "H3-D1"),
                       "deferral": "RUN-GATEWAY-ADOPT-001"}
# R08's durable-executor bullet carries these (R13 (a); O5).
H10_R08_EVIDENCE = ("PostgreSQL leases/outbox", "Temporal is a separate optional provider module")

TOP = ("schemaVersion", "adr", "policySha256", "catalogues", "repositories", "deployables", "outsideCatalogue",
       "exceptions", "baselineBindings", "h10Sources")
REPOSITORY_MEMBERS = ("id", "name", "rNumber", "languages", "toolchain", "sources")
TECH_MEMBERS = ("runtime", "frameworks", "packaging", "upstream", "implementationStatus", "decision")
DEPLOYABLE_MEMBERS = ("id", "ownerRepository", "kind", "plannedLanguage", "toolchain", "plane", "planeSource", "status",
                      "source", "runtime", "frameworks", "frameworksSources", "packaging", "upstream",
                      "implementationStatus", "decision")
OUTSIDE_MEMBERS = ("id", "ownerRepository", "plannedLanguage", "sources")
NATIVE_MEMBERS = OUTSIDE_MEMBERS + TECH_MEMBERS
EXCEPTION_MEMBERS = ("deployable", "status", "defaultLanguage", "plannedLanguage", "owner", "evidence", "reviewTrigger")
SPAN_MEMBERS = ("path", "section", "lines", "sha256", "evidence")
BINDING_MEMBERS = ("harness", "document", "delivery", "rows")
ROW_MEMBERS = ("baseline", "kind", "target")
DIVERGENCE_MEMBERS = ("roadmapSelection", "decisions", "deferral")
H10_MEMBERS = ("r08",)
HEX64 = re.compile(r"[0-9a-f]{64}")
R_NUMBER = re.compile(r"R[0-9]{2}")
REPO_PATH = re.compile(r"(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+")
PLAN_NAME = re.compile(r"([0-9]{2})-(.+)\.md")
# A span's `section`: '#' one to six times, a space, and the rest of one heading line (R1).
SECTION = re.compile(r"#{1,6} [^\r\n]*")
HEADING = re.compile(rb"#{1,6} ")
# The "Name version" prefix of a toolchain string: a name, a space, and a version token that starts with a digit (R4).
NAME_VERSION = re.compile(r"[A-Za-z][A-Za-z0-9+#._-]* [0-9]")
BACKTICKED = re.compile(r"`([^`\n]+)`")
TABLES = ("repositories", "deployables", "outsideCatalogue", "exceptions")
TABLE_TITLES = {"repositories": "Repositories", "deployables": "Deployables (architecture/services.yaml)",
                "outsideCatalogue": "Outside the catalogue", "exceptions": "Exceptions (LANG-D2 (b))"}
AMENDMENT_TABLES = ("technology", "native", "bindings")
AMENDMENT_TITLES = {"technology": "Technology (amendment 1)", "native": "Native rows (amendment 1)",
                    "bindings": "Baseline bindings (amendment 1)"}


class Refusal(ValueError):
    """The data, the ADR or a source breaks a rule; `rule` is R1 to R14."""

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


def _list(value: Any) -> list:
    return value if type(value) is list else []


# ---------------------------------------------------------------- R1 shape

def _str(value: Any) -> bool:
    return type(value) is str and value != ""


def _closed(value: Any, members: tuple) -> bool:
    return type(value) is dict and set(value) == set(members)


def _rel_path(value: Any) -> bool:
    return (_str(value) and REPO_PATH.fullmatch(value) is not None
            and all(part not in (".", "..") for part in value.split("/")))


def _strings(value: Any, low: int = 0) -> bool:
    """A list of at least `low` distinct non-empty strings."""
    return (type(value) is list and len(value) >= low and all(_str(x) for x in value)
            and len(set(value)) == len(value))


def _span(value: Any) -> bool:
    if not _closed(value, SPAN_MEMBERS):
        return False
    lines, evidence = value["lines"], value["evidence"]
    return (_rel_path(value["path"])
            and type(value["section"]) is str and SECTION.fullmatch(value["section"]) is not None
            and type(lines) is list and len(lines) == 2
            and all(type(n) is int for n in lines) and 1 <= lines[0] <= lines[1]
            and type(value["sha256"]) is str and HEX64.fullmatch(value["sha256"]) is not None
            and _strings(evidence, 1))


def _spans(value: Any) -> bool:
    return type(value) is list and 1 <= len(value) <= 2 and all(_span(s) for s in value)


def _tech(row: dict) -> bool:
    """The six technology members' types and enums (deployables and native rows)."""
    packaging, frameworks = row["packaging"], row["frameworks"]
    return ((row["runtime"] is None or _str(row["runtime"]))
            and type(frameworks) is list and all(_str(f) for f in frameworks)  # a repeated item is R11's
            and type(packaging) is list and all(type(p) is str and p in PACKAGING for p in packaging)
            and packaging == sorted(set(packaging))
            and (row["upstream"] is None or _str(row["upstream"]))
            and type(row["implementationStatus"]) is str and row["implementationStatus"] in IMPLEMENTATION_STATUSES
            and type(row["decision"]) is str and row["decision"] in DECISIONS)


def _target(kind: str, target: Any) -> bool:
    if not _closed(target, TARGET_MEMBERS[kind]):
        return False
    if kind == "PLAN_LIBRARY":
        return _span(target["span"])
    return all(_str(target[k]) for k in TARGET_MEMBERS[kind])


def _binding_row(row: Any) -> bool:
    if not (type(row) is dict and set(row) in (set(ROW_MEMBERS), set(ROW_MEMBERS) | {"divergence"})):
        return False
    if not (_str(row["baseline"]) and type(row["kind"]) is str and row["kind"] in BINDING_KINDS
            and _target(row["kind"], row["target"])):
        return False
    if "divergence" in row:
        div = row["divergence"]
        return (_closed(div, DIVERGENCE_MEMBERS) and _str(div["roadmapSelection"]) and _strings(div["decisions"], 1)
                and _str(div["deferral"]))
    return True


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
    for key in ("repositories", "deployables", "outsideCatalogue", "exceptions", "baselineBindings"):
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
        _refuse(_tech(row), rule, row["id"] + ": the technology members' types and enums (PACKAGING, "
                "IMPLEMENTATION_STATUSES, DECISIONS)")
        _refuse(type(row["frameworksSources"]) is list and all(_span(s) for s in row["frameworksSources"]), rule,
                row["id"] + ": frameworksSources is a list of closed spans")
    for row in data["outsideCatalogue"]:
        native = type(row) is dict and row.get("id") in NATIVE_ROWS
        members = NATIVE_MEMBERS if native else OUTSIDE_MEMBERS
        _refuse(_closed(row, members), rule, "an outside row is closed: " + ", ".join(members))
        _refuse(_str(row["id"]) and _str(row["ownerRepository"]), rule, "an outside row's id and owner are strings")
        _refuse(type(row["plannedLanguage"]) is str and row["plannedLanguage"] in LANGUAGES, rule,
                "plannedLanguage is one of " + ", ".join(LANGUAGES))
        _refuse(_spans(row["sources"]), rule, "an outside row has 1 or 2 closed spans")
        if native:
            _refuse(_tech(row), rule, row["id"] + ": the technology members' types and enums")
    for row in data["exceptions"]:
        _refuse(_closed(row, EXCEPTION_MEMBERS), rule, "an exception row is closed: " + ", ".join(EXCEPTION_MEMBERS))
        _refuse(all(_str(row[k]) for k in ("deployable", "evidence", "reviewTrigger")), rule,
                "an exception row's deployable, evidence and reviewTrigger are strings")
        _refuse(type(row["status"]) is str and row["status"] in STATUSES, rule, "status is one of " + ", ".join(STATUSES))
        for key in ("defaultLanguage", "plannedLanguage"):
            _refuse(type(row[key]) is str and row[key] in LANGUAGES, rule, key + " is one of " + ", ".join(LANGUAGES))
        _refuse(_closed(row["owner"], ("repository", "packet")) and _str(row["owner"]["repository"])
                and _str(row["owner"]["packet"]), rule, "owner is a closed {repository, packet} object")
    for entry in data["baselineBindings"]:
        _refuse(_closed(entry, BINDING_MEMBERS), rule, "a binding entry is closed: " + ", ".join(BINDING_MEMBERS))
        _refuse(_str(entry["harness"]) and _span(entry["document"]) and _span(entry["delivery"]), rule,
                "a binding entry has a harness and two closed spans")
        _refuse(type(entry["rows"]) is list and len(entry["rows"]) >= 1, rule, "a binding entry has rows")
        for row in entry["rows"]:
            _refuse(_binding_row(row), rule, entry["harness"] + ": a binding row is a closed {baseline, kind, target} "
                    "(with an optional closed divergence), its target closed per kind")
    _refuse(_closed(data["h10Sources"], H10_MEMBERS) and _span(data["h10Sources"]["r08"]), rule,
            "h10Sources is a closed {r08: span} object")


# ---------------------------------------------------------------- R2 catalogues and policy

def _catalogues(data: dict, root: Path, overlay: dict) -> tuple:
    rule = "R2"
    _refuse([c["path"] for c in data["catalogues"]] == list(CATALOGUES), rule,
            "catalogues are exactly " + ", ".join(CATALOGUES) + ", in that order")
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


def _providers(root: Path, overlay: dict) -> dict:
    """providers.yaml, pinned by R2's digest: modules with unique ids, service bindings with unique service ids, and
    the capability and exclusivity lists R10, R12 and R13 read."""
    rule = "R2"
    providers = _yaml(_read(root, overlay, PROVIDERS_PATH, rule), PROVIDERS_PATH)
    _refuse(type(providers) is dict and type(providers.get("modules")) is list
            and all(type(m) is dict and _str(m.get("id")) for m in providers["modules"]), rule,
            "providers.yaml lists modules with ids")
    ids = [m["id"] for m in providers["modules"]]
    _refuse(len(set(ids)) == len(ids), rule, "providers.yaml's module ids are unique")
    bindings = providers.get("serviceModuleBindings")
    _refuse(type(bindings) is list and all(type(b) is dict and _str(b.get("serviceId")) and _str(b.get("moduleId"))
                                           for b in bindings), rule,
            "providers.yaml lists serviceModuleBindings with serviceId and moduleId")
    services = [b["serviceId"] for b in bindings]
    _refuse(len(set(services)) == len(services), rule, "providers.yaml binds each service once")
    for key in ("capabilityProviders", "providerExclusivityGroups"):
        _refuse(type(providers.get(key)) is list and all(type(e) is dict for e in providers[key]), rule,
                "providers.yaml's " + key + " is a list of objects")
    return providers


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


# ---------------------------------------------------------------- R4 repositories and toolchains

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


def _toolchains(data: dict) -> None:
    """C1-3: every toolchain string is its row's closed constant, and a non-UPSTREAM_OWN one begins "Name version"."""
    rule = "R4"
    for table in ("repositories", "deployables"):
        expected = TOOLCHAIN_EXPECTED[table]
        for row in data[table]:
            _refuse(row["id"] in expected and row["toolchain"] == expected[row["id"]], rule,
                    "%s %s: toolchain is %r" % (table, row["id"], expected.get(row["id"])))
            if row.get("plannedLanguage") != "UPSTREAM_OWN":
                _refuse(NAME_VERSION.match(row["toolchain"]) is not None, rule,
                        "%s %s: toolchain does not begin with a name and a version" % (table, row["id"]))


# ---------------------------------------------------------------- R5 sources

def _has_token(evidence: list, language: str) -> bool:
    return any(token in evidence for token in LANG_TOKEN[language])


def id_token(deployable: str) -> str:
    return ALIAS.get(deployable, "`" + deployable + "`")


def locate(raw: bytes, count: int, sha256: str, first: int = 1) -> bytes | None:
    """v1's content location (MET-GOV-004 errata 2), kept for reference: the block of exactly `count` contiguous whole
    lines of `raw` whose sha256 is `sha256`, wherever it lies in the file, or None. v2's R5 uses locate_in_section."""
    lines = _lines(raw)
    starts = range(len(lines) - count + 1)
    for start in ([first - 1] if 0 <= first - 1 < len(starts) else []) + list(starts):
        chunk = b"".join(lines[start:start + count])
        if hashlib.sha256(chunk).hexdigest() == sha256:
            return chunk
    return None


def section_lines(raw: bytes, section: str) -> tuple:
    """(how many heading lines equal `section`, the section's lines): when there is exactly one, the lines after it up
    to the next heading line of any level, each with its line feed (C2-2, MON-TT-D1)."""
    lines = _lines(raw)
    wanted = section.encode("utf-8")
    heads = [i for i, line in enumerate(lines) if HEADING.match(line) and line.rstrip(b"\n") == wanted]
    if len(heads) != 1:
        return len(heads), []
    end = next((i for i in range(heads[0] + 1, len(lines)) if HEADING.match(lines[i])), len(lines))
    return 1, lines[heads[0] + 1:end]


def locate_in_section(raw: bytes, section: str, count: int, sha256: str) -> tuple:
    """(heading count, every block of exactly `count` whole lines inside the section whose sha256 is `sha256`)."""
    heads, body = section_lines(raw, section)
    chunks = [b"".join(body[s:s + count]) for s in range(len(body) - count + 1)]
    return heads, [c for c in chunks if hashlib.sha256(c).hexdigest() == sha256]


def _block(span: dict, root: Path, overlay: dict, cache: dict, rule: str) -> str:
    """The text of the span's one block in its section (R5 has located it)."""
    path, (first, last) = span["path"], span["lines"]
    if path not in cache:
        cache[path] = _read(root, overlay, path, rule)
    heads, chunks = locate_in_section(cache[path], span["section"], last - first + 1, span["sha256"])
    _refuse(heads == 1 and len(chunks) == 1, rule, "%s:%d-%d is not located in %r" % (path, first, last,
                                                                                      span["section"]))
    return _text(chunks[0], rule, path)


def _span_text(span: dict, root: Path, overlay: dict, cache: dict, roots: tuple = V1_ROOTS) -> str:
    rule = "R5"
    path, (first, last) = span["path"], span["lines"]
    _refuse(path.startswith(roots), rule, "%s: this span may cite only %s" % (path, " or ".join(roots)))
    if path not in cache:
        cache[path] = _read(root, overlay, path, rule)
    heads, chunks = locate_in_section(cache[path], span["section"], last - first + 1, span["sha256"])
    _refuse(heads == 1, rule, "%s: the heading %r occurs %d times as a heading line" % (path, span["section"], heads))
    _refuse(len(chunks) == 1, rule, "%s: %d blocks of %d lines (cited at %d-%d) in %r match its digest"
            % (path, len(chunks), last - first + 1, first, last, span["section"]))
    text = _text(chunks[0], rule, path)
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
    for row in data["deployables"]:
        for span in row["frameworksSources"]:
            _span_text(span, root, overlay, cache, PLAN_ROOTS)
            count += 1
    for entry in data["baselineBindings"]:
        for span in (entry["document"], entry["delivery"]):
            _span_text(span, root, overlay, cache, HARNESS_ROOTS)
            count += 1
        for row in entry["rows"]:
            if row["kind"] == "PLAN_LIBRARY":
                _span_text(row["target"]["span"], root, overlay, cache, PLAN_ROOTS)
                count += 1
    _span_text(data["h10Sources"]["r08"], root, overlay, cache, PLAN_ROOTS)
    return count + 1


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


# ---------------------------------------------------------------- R9 technology fields

def _tech_values(row: dict) -> tuple:
    return (row["runtime"], tuple(row["packaging"]), row["upstream"], row["implementationStatus"], row["decision"])


def _technology(data: dict) -> None:
    rule = "R9"
    rows = data["deployables"] + [r for r in data["outsideCatalogue"] if r["id"] in NATIVE_ROWS]
    for row in rows:
        _refuse(row["id"] in TECH_EXPECTED and _tech_values(row) == TECH_EXPECTED[row["id"]], rule,
                row["id"] + ": (runtime, packaging, upstream, implementationStatus, decision) is %r"
                % (TECH_EXPECTED.get(row["id"]),))


# ---------------------------------------------------------------- R10 catalog agreement

def _catalog_agreement(data: dict, services: dict, providers: dict) -> None:
    rule = "R10"
    catalogued = {s["id"]: s for s in services["services"]}
    modules = {m["id"]: m for m in providers["modules"]}
    bound = {b["serviceId"]: b["moduleId"] for b in providers["serviceModuleBindings"]}
    for row in data["deployables"]:
        d = row["id"]
        module = bound.get(d)
        _refuse(module is not None and module.endswith("." + d), rule,
                d + ": serviceModuleBindings binds it to a module ending in ." + d)
        _refuse(module in modules, rule, d + ": its module " + module + " is a providers.yaml record")
        units = [u for u in _list(modules[module].get("installUnits")) if type(u) is dict]
        types = sorted({u["type"] for u in units if _str(u.get("type"))})
        _refuse(row["packaging"] == types, rule, d + ": packaging is its module's install-unit types %s" % types)
        third = [u["artifact"] for u in units if u.get("type") == "OCI_IMAGE" and _str(u.get("artifact"))
                 and not u["artifact"].startswith(FIRST_PARTY_PREFIX)]
        upstream = third[0] if len(third) == 1 else None
        _refuse(row["upstream"] == upstream, rule, d + ": upstream is its module's third-party image %r" % (upstream,))
        status = UPSTREAM_MANAGED if upstream is not None else catalogued[d].get("implementationStatus")
        _refuse(row["implementationStatus"] == status, rule, d + ": implementationStatus is %r" % (status,))
        _refuse(row["implementationStatus"] not in UNSTATED_AT_BASE, rule,
                d + ": APPROVED and IMPLEMENTED are refused: no harness-onion record states either")


# ---------------------------------------------------------------- R11 frameworks

def whole_word(item: str) -> re.Pattern:
    """`item` with no adjoining letter, digit, '_', '+' or '-' on either side (TT-D1-6)."""
    return re.compile(r"(?<![A-Za-z0-9_+-])" + re.escape(item) + r"(?![A-Za-z0-9_+-])")


def _frameworks(data: dict, root: Path, overlay: dict) -> None:
    rule = "R11"
    cache: dict = {}
    for row in data["deployables"]:
        d, items = row["id"], row["frameworks"]
        _refuse(d in FRAMEWORKS_EXPECTED and items == list(FRAMEWORKS_EXPECTED[d]), rule,
                d + ": frameworks are %r" % (FRAMEWORKS_EXPECTED.get(d),))
        _refuse(len(set(items)) == len(items), rule, d + ": a framework is listed twice")
        _refuse(row["runtime"] not in items, rule, d + ": the runtime is not a framework")
        if row["plannedLanguage"] != "UPSTREAM_OWN":
            _refuse(len(row["frameworksSources"]) >= 1, rule, d + ": a non-UPSTREAM_OWN deployable has a source")
        texts = []
        for span in row["frameworksSources"]:
            _refuse(span["section"] == TOOLCHAIN_SECTION, rule, d + ": a frameworks source is in " + TOOLCHAIN_SECTION)
            texts.append(_block(span, root, overlay, cache, rule))
        for item in items:
            _refuse(any(whole_word(item).search(t) for t in texts), rule,
                    d + ": %r is not a whole word of its frameworks sources" % item)
    for row in data["outsideCatalogue"]:
        if row["id"] in NATIVE_ROWS:
            _refuse(row["frameworks"] == [], rule, row["id"] + ": a native row's frameworks are []")


# ---------------------------------------------------------------- R12 baseline bindings

def _target_key(row: dict) -> tuple:
    """The compared part of a target (BR-TT-1): a PLAN_LIBRARY span by (path, section, sha256, evidence)."""
    target = row["target"]
    if row["kind"] == "PLAN_LIBRARY":
        span = target["span"]
        return (span["path"], span["section"], span["sha256"], tuple(span["evidence"]))
    return tuple(target[k] for k in TARGET_MEMBERS[row["kind"]])


def _bindings(data: dict, providers: dict, root: Path, overlay: dict) -> None:
    rule = "R12"
    cache: dict = {}
    entries = data["baselineBindings"]
    for entry in entries:
        own = "%s/%s.md" % (HARNESSES_DIR, entry["harness"])
        _refuse(entry["document"]["path"] == own and entry["delivery"]["path"] == own, rule,
                entry["harness"] + ": its document and delivery spans are in " + own)
    _refuse([e["harness"] for e in entries] == list(STEMS), rule, "the harness entries are STEMS, in order")
    flat = [(e["harness"], r["baseline"], r["kind"], _target_key(r)) for e in entries for r in e["rows"]]
    expected = [tuple(x) for x in BINDINGS_EXPECTED]
    differ = next((i for i, (a, b) in enumerate(zip(flat, expected)) if a != b), min(len(flat), len(expected)))
    _refuse(flat == expected, rule, "the binding rows are BINDINGS_EXPECTED, in order (first difference at row %d)"
            % (differ + 1))
    modules = {m["id"]: m for m in providers["modules"]}
    for entry in entries:
        harness = entry["harness"]
        document = _block(entry["document"], root, overlay, cache, rule)
        delivery = _block(entry["delivery"], root, overlay, cache, rule)
        _refuse(BACKTICKED.findall(document) == [r["baseline"] for r in entry["rows"]], rule,
                harness + ": its document span holds exactly its rows' upstreams, in order, as backticked tokens")
        for row in entry["rows"]:
            kind, target = row["kind"], row["target"]
            if kind in SELECTIONS:
                module = modules.get(target["record"])
                _refuse(module is not None, rule, harness + ": " + target["record"] + " is a providers.yaml record")
                _refuse(target["token"] in _list(module.get("providers")), rule,
                        harness + ": " + target["token"] + " is in " + target["record"] + "'s providers")
                _refuse(module.get("selection") in SELECTIONS[kind], rule, harness + ": " + target["record"]
                        + "'s selection is " + " or ".join(SELECTIONS[kind]) + " for " + kind)
            elif kind == "PLAN_LIBRARY":
                token = PLAN_TOKENS.get(row["baseline"])
                text = _block(target["span"], root, overlay, cache, rule)
                _refuse(target["span"]["section"] == TOOLCHAIN_SECTION and text.startswith("- ") and _str(token)
                        and whole_word(token).search(text) is not None, rule,
                        harness + ": " + row["baseline"] + "'s plan span is a toolchain bullet carrying %r" % (token,))
            else:
                _refuse("`%s`" % target["item"] in delivery, rule,
                        harness + ": " + target["item"] + " occurs backticked on its Delivery line")
    divergent = [(e["harness"], r["baseline"], r["divergence"]) for e in entries for r in e["rows"]
                 if "divergence" in r]
    _refuse(len(divergent) == 1 and divergent[0][:2] == DIVERGENCE_ROW, rule,
            "exactly one divergence, on %s %s" % DIVERGENCE_ROW)
    divergence = divergent[0][2]
    _refuse(divergence["roadmapSelection"] == DIVERGENCE_EXPECTED["roadmapSelection"]
            and tuple(divergence["decisions"]) == tuple(DIVERGENCE_EXPECTED["decisions"])
            and divergence["deferral"] == DIVERGENCE_EXPECTED["deferral"], rule,
            "the divergence is DIVERGENCE_EXPECTED %r" % (DIVERGENCE_EXPECTED,))
    owner = next(e for e in entries if e["harness"] == DIVERGENCE_ROW[0])
    _refuse("`%s`" % divergence["deferral"] in _block(owner["delivery"], root, overlay, cache, rule), rule,
            "the divergence's deferral occurs backticked on " + DIVERGENCE_ROW[0] + "'s Delivery line")


# ---------------------------------------------------------------- R13 drift

def _drift(data: dict, providers: dict, root: Path, overlay: dict) -> None:
    rule = "R13"
    text = _block(data["h10Sources"]["r08"], root, overlay, {}, rule)
    for evidence in H10_R08_EVIDENCE:
        _refuse(evidence in text, rule, "R08's executor line does not carry %r" % evidence)
    for module in providers["modules"]:
        if module.get("selection") in ("DEFAULT", "CONDITIONAL"):
            names = ([module["id"]] + [p for p in _list(module.get("providers")) if type(p) is str]
                     + [u["artifact"] for u in _list(module.get("installUnits"))
                        if type(u) is dict and type(u.get("artifact")) is str])
            _refuse(not any(TEMPORAL in n.lower() for n in names), rule,
                    module["id"] + ": a DEFAULT or CONDITIONAL record names Temporal, which ADR 0011 makes optional")
    modules = {m["id"]: m for m in providers["modules"]}
    grouped = {m for g in providers["providerExclusivityGroups"] for m in _list(g.get("members"))}
    for entry in data["baselineBindings"]:
        bound = []
        for row in entry["rows"]:
            if row["kind"] in SELECTIONS and row["target"]["record"] not in bound:
                bound.append(row["target"]["record"])
        for record in bound:
            _refuse(not (record in grouped and modules[record].get("selection") == "DEFAULT"), rule,
                    entry["harness"] + ": " + record + " is DEFAULT in a providerExclusivityGroup")
        for capability in providers["capabilityProviders"]:
            defaults = [r for r in bound if r in _list(capability.get("modules"))
                        and modules[r].get("selection") == "DEFAULT"]
            _refuse(len(defaults) <= 1, rule, "%s: two DEFAULT records for capability %s: %s"
                    % (entry["harness"], capability.get("capability"), ", ".join(defaults)))


# ---------------------------------------------------------------- R14 upstream language

def _r14(data: Any) -> None:
    """R14 over the data's deployables, or over a list of deployable rows (BR-TT-2's direct tests): a deployable with an
    upstream is UPSTREAM_OWN, and an UPSTREAM_OWN deployable has an upstream."""
    rule = "R14"
    rows = data["deployables"] if type(data) is dict else data
    for row in rows:
        upstream, language = row.get("upstream"), row.get("plannedLanguage")
        _refuse(upstream is None or language == "UPSTREAM_OWN", rule,
                "%s: a deployable with an upstream keeps the upstream's language, UPSTREAM_OWN" % row.get("id"))
        _refuse(language != "UPSTREAM_OWN" or upstream is not None, rule,
                "%s: an UPSTREAM_OWN deployable has an upstream" % row.get("id"))


# ---------------------------------------------------------------- R8 the ADR's tables

def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|")


def _where(span: dict) -> str:
    first, last = span["lines"]
    return "`%s:%d`" % (span["path"], first) if first == last else "`%s:%d-%d`" % (span["path"], first, last)


def _row(cells: list) -> str:
    return "| " + " | ".join(_cell(c) for c in cells) + " |"


def _value(value: Any) -> str:
    return "null" if value is None else value


def _items(items: list) -> str:
    return ", ".join(items) if items else "none"


def _target_cell(row: dict) -> str:
    target = row["target"]
    if row["kind"] in SELECTIONS:
        return "`%s` / `%s`" % (target["record"], target["token"])
    if row["kind"] == "PLAN_LIBRARY":
        span = target["span"]
        return "`%s` under `%s`: %s" % (span["path"], span["section"], ", ".join(span["evidence"]))
    return "%s (Delivery line)" % target["item"]


def _divergence_cell(row: dict) -> str:
    if "divergence" not in row:
        return "none"
    div = row["divergence"]
    return "roadmap selection %s (%s), deferral %s; recorded, not resolved" % (
        div["roadmapSelection"], ", ".join(div["decisions"]), div["deferral"])


def _render_amendment(data: dict, table: str) -> list:
    """An amendment table block: a caption that pins providers.yaml by sha256 (and names neither services.yaml's nor
    repositories.yaml's digest), a blank line and the table, rows in the data's order."""
    cats = {c["path"]: c["sha256"] for c in data["catalogues"]}
    caption = ("%s, rendered from `%s` (schema `%s`) by `scripts/language_placement.py`: the baseline at `%s` sha256 "
               "`%s`." % (AMENDMENT_TITLES[table], DATA_PATH, SCHEMA_VERSION, PROVIDERS_PATH, cats.get(PROVIDERS_PATH)))
    if table == "technology":
        head = ["Deployable", "Runtime", "Frameworks", "Packaging", "Upstream", "Implementation status", "Decision",
                "Frameworks sources"]
        rows = [["`%s`" % r["id"], _value(r["runtime"]), _items(r["frameworks"]), ", ".join(r["packaging"]),
                 _value(r["upstream"]), r["implementationStatus"], r["decision"],
                 "; ".join(_where(s) for s in r["frameworksSources"]) or "none"] for r in data["deployables"]]
    elif table == "native":
        head = ["Row", "Owner repository", "Runtime", "Frameworks", "Packaging", "Upstream", "Implementation status",
                "Decision"]
        rows = [["`%s`" % r["id"], "`%s`" % r["ownerRepository"], _value(r["runtime"]), _items(r["frameworks"]),
                 ", ".join(r["packaging"]), _value(r["upstream"]), r["implementationStatus"], r["decision"]]
                for r in data["outsideCatalogue"] if r["id"] in NATIVE_ROWS]
    else:
        head = ["Harness", "Baseline", "Kind", "Target", "Divergence"]
        rows = [["`%s`" % e["harness"], "`%s`" % r["baseline"], r["kind"], _target_cell(r), _divergence_cell(r)]
                for e in data["baselineBindings"] for r in e["rows"]]
    return [caption, "", _row(head), "|" + "---|" * len(head)] + [_row(r) for r in rows]


def render(data: dict, table: str) -> list:
    """The deterministic rendering of one table block, as lines: a caption that pins the catalogues by sha256 (the
    baseline its rows are taken at), a blank line and the table, rows in the data's order. The four v1 tables pin
    services.yaml and repositories.yaml; the amendment's three (AMENDMENT_TABLES) pin providers.yaml."""
    if table in AMENDMENT_TABLES:
        return _render_amendment(data, table)
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
    if table in AMENDMENT_TABLES:
        return "<!-- %s-table:begin -->" % table, "<!-- %s-table:end -->" % table
    return "<!-- language-placement:%s:begin -->" % table, "<!-- language-placement:%s:end -->" % table


def _tables(data: dict, adr: str, tables: tuple = TABLES) -> None:
    rule = "R8"
    lines = adr.split("\n")
    for table in tables:
        begin, end = _markers(table)
        _refuse(lines.count(begin) == 1 and lines.count(end) == 1, rule, "the ADR has one " + table + " block")
        a, b = lines.index(begin), lines.index(end)
        _refuse(a < b and lines[a + 1:b] == render(data, table), rule,
                "the ADR's " + table + " table is not the data's rendering")


# ---------------------------------------------------------------- the check

def check(root: Path = ROOT, overlay: dict | None = None) -> dict:
    """R1-R7, R9-R14, then R8, over the tree at `root`; `overlay` maps repository paths to bytes that stand in for the
    tree's (for in-memory checks). Raises Refusal(rule, message) on the first rule broken; otherwise returns the
    counts."""
    root = Path(root)
    overlay = dict(overlay or {})
    raw = _read(root, overlay, DATA_PATH, "R1")
    try:
        data = strict(raw)
    except (ValueError, RecursionError) as exc:
        raise Refusal("R1", "%s: %s" % (DATA_PATH, exc if type(exc) is ValueError else type(exc).__name__)) from None
    _shape(data)
    services, repositories = _catalogues(data, root, overlay)
    providers = _providers(root, overlay)
    adr = _text(_read(root, overlay, ADR_PATH, "R2"), "R2", ADR_PATH)
    _policy(data, adr)
    deployables = _deployables(data, services)
    _repositories(data, repositories, root, overlay)
    _toolchains(data)
    spans = _sources(data, root, overlay)
    _outside(data)
    _exceptions(data, deployables, services)
    _technology(data)
    _catalog_agreement(data, services, providers)
    _frameworks(data, root, overlay)
    _bindings(data, providers, root, overlay)
    _drift(data, providers, root, overlay)
    _r14(data)
    _tables(data, adr)
    _tables(data, adr, AMENDMENT_TABLES)
    by_status = {s: sum(1 for r in data["deployables"] if r["status"] == s) for s in STATUSES}
    by_plane = {p: sum(1 for r in data["deployables"] if r["plane"] == p) for p in PLANES}
    by_implementation = {s: sum(1 for r in data["deployables"] if r["implementationStatus"] == s)
                         for s in IMPLEMENTATION_STATUSES}
    rows = [r for e in data["baselineBindings"] for r in e["rows"]]
    by_kind = {k: sum(1 for r in rows if r["kind"] == k) for k in BINDING_KINDS}
    return {"repositories": len(data["repositories"]), "deployables": len(data["deployables"]),
            "byStatus": by_status, "byPlane": by_plane, "outsideCatalogue": len(data["outsideCatalogue"]),
            "exceptions": len(data["exceptions"]), "spans": spans,
            "byImplementationStatus": by_implementation,
            "nativeRows": sum(1 for r in data["outsideCatalogue"] if r["id"] in NATIVE_ROWS),
            "harnesses": len(data["baselineBindings"]), "bindings": len(rows), "byKind": by_kind}


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
    print("technology record (amendment 1): implementation %s; %d native rows; %d harnesses, %d bindings (%s); the "
          "three amendment tables match"
          % (", ".join("%s %d" % kv for kv in summary["byImplementationStatus"].items()), summary["nativeRows"],
             summary["harnesses"], summary["bindings"], ", ".join("%s %d" % kv for kv in summary["byKind"].items())))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
