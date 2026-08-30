# Repository Plan: `mas-harness-sdks`

## Purpose and boundaries

This repository provides generated contract clients and tenant-neutral application/runtime SDKs. It owns instrumentation helpers, context propagation, signed-runtime admission, MCP/A2A client helpers, receipts, guardrail clients, and a temporary legacy Python compatibility distribution.

Non-goals:

- No deployable model, orchestration, guardrail, policy, or telemetry service.
- No schema ownership; generated types come from a pinned `mas-harness-contracts` release.
- No hosted-provider integration in core or default extras.
- New platform services must not import the legacy `prometa` namespace.

## Repository structure and exact tree

This tree projects the current task-packet `allowedPaths`. Directory entries do not authorize edits beyond the packet executed in a coding run.

```text
mas-harness-sdks/
├── .github/workflows/verify.yml
├── .gitignore
├── AGENTS.md
├── CONTRIBUTING.md
├── LICENSE
├── NOTICE
├── README.md
├── SECURITY.md
├── PORTING.yaml
├── Makefile
├── contracts.lock.json
├── ci/
├── python/
│   ├── compat-pyproject.toml
│   ├── optional-dependencies.lock
│   ├── compat/prometa/
│   ├── src/planeon_harness/
│   │   ├── attributes.py
│   │   ├── authz.py
│   │   ├── budget.py
│   │   ├── context.py
│   │   ├── decorators.py
│   │   ├── protocols/
│   │   ├── guardrails/
│   │   ├── runtime/
│   │   └── integrations/
│   └── tests/{compat,guardrail,integrations,protocols,runtime,telemetry}/
├── typescript/
│   ├── src/{guardrail,protocols,runtime,telemetry}/
│   └── tests/{guardrail,protocols,runtime,telemetry}/
├── generators/
├── fixtures/{guardrail,protocols,runtime}/
├── tests/generated/
├── examples/{integrations,telemetry}/
└── docs/{compatibility-matrix.md,protocol-support.md,migrations/prometa.md}
```

## Packages, toolchain, and interfaces

- Python core: distribution `planeon-harness-sdk`, import `planeon_harness`, Python 3.10-3.13 with development baseline 3.12.14, built by Hatchling and locked with `uv` 0.12.7.
- Python compatibility: distribution `planeon-prometa-compat`, import `prometa`, versioned with core through `v1.x`; it contains re-exports and deprecation warnings only.
- TypeScript: package `@planeon/harness-sdk`, Node 24.20.0 LTS, TypeScript 5.x, ESM, `package-lock.json`, and no postinstall network action.
- Generated types and clients cover all OpenAPI schemas, CloudEvents, error envelopes, idempotency keys, ETags, and operations.
- Handwritten APIs cover tenant context, OTel attributes/decorators, trace/baggage propagation, signed-bundle admission, policy/guardrail clients, task polling/SSE, MCP/A2A adapters, idempotent receipts, budgets, resilience, and framework instrumentation.
- Stores: SDK runtime helpers may target a caller-supplied PostgreSQL connection through the `runtime-postgres` extra, but the SDK owns no migrations or database service.
- Events: typed constructors/parsers for all `HarnessCloudEvent` variants; SDKs never publish automatically without a caller-supplied transport.

Public telemetry remains tenant-neutral: examples use `mcp.integration.*`, `acme.mcp.*`, and `your.integration.*`. Tenant identity is accepted only from authenticated caller context, not untrusted metadata.

## Task-command ownership

The bootstrap packet is the sole current owner of `Makefile` and installs the
closed `ci/run_make_target.py` direct-argv dispatcher. Each later Make-using
packet owns only `ci/targets/<lowercase-packet-id>.json`, which registers its
exact targets, closed variable values, and packet-local handlers. The dispatcher
validates descriptors and executes every applicable handler cumulatively in
lexical packet order; missing, ambiguous, duplicate, undeclared-variable, or
shell-based handlers fail closed. Later packets never edit `Makefile`. The only
exception is the generic `campaign`, `evidence-verify`, and
`acceptance-package` dispatch owned and tested by `CONF-001` for conformance
campaign packets.

The same bootstrap packet is the only current owner of `PORTING.yaml` and
seeds a closed `NO_AUTHORIZATION` ledger. Reference/discovery-only packets cannot
edit it; a future copy transaction requires a revised `PORT_CANDIDATE` packet.

## Dependencies

- Upstream: exact contracts release/digest in `contracts.lock.json`.
- Downstream: control, runtime, model, knowledge, execution, trust, operator tooling, and external adopters.
- Core Python and TypeScript packages have minimal dependencies; framework integrations are optional extras/entry points. Paid, metered, hosted-provider, and third-party-API-key extras are never built or documented.

## Warm-source mapping

Public source provenance is recorded only in `architecture/reuse-map.yaml`, `architecture/reuse-path-index.yaml`, and packet `sourceReuse` entries. Non-public planning inputs have already been distilled into independent public contracts and acceptance criteria; their repository names, commits, paths, and object IDs are deliberately omitted. They are not mounted or required during implementation. No source is copy-authorized.

## PR packets

1. `SDK-001-bootstrap-generated`: toolchains, contract lock, deterministic generators, generated clients, and drift check.
2. `SDK-002-telemetry`: context, neutral semantic attributes, decorators, OTel vectors, and framework-neutral examples.
3. `SDK-003-admission-trust`: signed admission, trust roots, receipts, idempotency, budgets, and runtime-control vectors.
4. `SDK-004-protocols`: MCP 2026-07-28 plus 2025-11-25 compatibility, A2A v1 task helpers, SSE resume, and CloudEvents.
5. `SDK-005-integrations`: LangChain, LangGraph, CrewAI, Semantic Kernel, MCP, and vector integrations as optional extras.
6. `SDK-006-guardrails`: profiles, streaming evaluation, detector contract, client, and conformance vectors.
7. `SDK-007-compat`: `planeon-prometa-compat`, legacy import tests, warnings, support matrix, and v1 removal notice.

## Testing, verification, and acceptance

The `SDK-001` bootstrap packet declares
`prefetchCommands: [["make","prefetch"]]` and ordered
`offlineAcceptanceCommands:
[["make","generated-check"],["make","build-reproducible"]]`.
Later packets add Python, TypeScript, contract, and zero-bill checks as direct
argv arrays. The executor supplies the hash-pinned packet through
`HARNESS_TASK_PACKET` and invokes only `offlineExecution.wrapperArgv:
["./ci/verify-offline.sh"]` for the complete ordered list.

The packet-owned offline suite uses locked local dependencies, Ruff, mypy,
pytest with at least 95% branch coverage on admission/trust/receipts, offline
npm inputs, TypeScript typecheck, and unit/golden tests. Generated output must
be clean after regeneration. Python and TypeScript serialize every golden
vector byte-identically after canonicalization.

## Release and rollback

- Release Python core, Python compatibility, and TypeScript packages with the same SemVer and contracts digest; sign local artifacts offline and place them in the distribution bundle, not PyPI/npm/GitHub Packages by default.
- Runtime services pin exact wheel/tarball digests. Rollback selects the previous package digest.
- Compatibility distribution lasts through the full v1 line; removal requires v2 and a migration report.

## Zero-bill rules

- No default provider credentials, hosted-provider clients, automatic exporters, phone-home checks, remote feature flags, or runtime downloads.
- Examples run against mocks or loopback local services only.
- CI uses self-hosted runners and local package caches populated only by `make prefetch`; no GitHub artifacts/caches/Packages, scheduled jobs, or remote coverage service.
