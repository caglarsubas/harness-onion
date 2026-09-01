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
│   ├── runtime-dependencies.lock.json
│   ├── compat/prometa/
│   ├── src/planeon_harness/
│   │   ├── attributes.py
│   │   ├── authz.py
│   │   ├── budget.py
│   │   ├── context.py
│   │   ├── decorators.py
│   │   ├── protocols/
│   │   ├── guardrail/
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
- Python compatibility: distribution `planeon-prometa-compat`, import `prometa`, exact-versioned with core before v2; SDK-007 approves only five clean-room alias modules, re-exports, and one deprecation warning. It does not claim parity with an unobserved historical implementation.
- TypeScript: package `@planeon/harness-sdk`, pinned Node 24.19.0, TypeScript 5.x, ESM, a committed toolchain lock, and no postinstall network action.
- Generated types and clients cover all OpenAPI schemas, CloudEvents, error envelopes, idempotency keys, ETags, and operations.
- Handwritten APIs cover tenant context, OTel attributes/decorators, trace/baggage propagation, signed-bundle admission, policy/guardrail clients, task polling/SSE, MCP/A2A adapters, idempotent receipts, budgets, resilience, and framework instrumentation.
- `SDK-003` consumes the exact `CON-007` release digest. Python Ed25519 uses a hash-pinned `cryptography` wheel from the preprovisioned offline wheelhouse; TypeScript uses the runtime Web Crypto implementation. Neither language may ship custom cryptographic primitives, fetch packages at runtime, or hold private keys.
- The Python dependency lock, TypeScript export map, contract snapshot, generated models, and committed source/dist runtime surfaces are part of the same packet boundary so consumers cannot observe a partial admission API.
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
3. `SDK-003-admission-trust`: consume the pinned runtime-admission contract release; implement signed admission, trust roots, receipts, idempotency, budgets, and runtime-control vectors with audited platform cryptography.
4. `SDK-004-protocols`: MCP 2026-07-28 plus 2025-11-25 compatibility, A2A v1 task helpers, SSE resume, and CloudEvents.
5. `SDK-005-integrations`: LangChain, LangGraph, CrewAI, Semantic Kernel, MCP, and vector integrations as optional extras.
6. `SDK-006-guardrails`: profiles, streaming evaluation, detector contract, client, and conformance vectors.
7. `SDK-007-compat`: `planeon-prometa-compat`, five newly approved migration aliases, wheel-isolated identity tests, a fixed warning, support matrix, and v2 removal notice.

### SDK-005 integration contract

SDK-005 is Python-only and instruments explicit caller invocations; it does not
patch frameworks, discover plugins, auto-register hooks, create clients, or own
network configuration. The base package and `planeon_harness.integrations`
import without any optional framework. A framework-specific factory performs
the first framework import and fails with the closed
`OPTIONAL_INTEGRATION_UNAVAILABLE` code and exact install-extra name when that
dependency is absent.

The packaging and compatibility surfaces are one atomic packet. The five PEP
508 extras are `langchain` (`langchain-core>=1.6,<2`), `langgraph`
(`langgraph>=1.2,<2`), `crewai` (`crewai>=1.15,<2`), `semantic-kernel`
(`semantic-kernel>=1.44,<2`), and `mcp` (`mcp>=2.1,<3`). The
`python/optional-dependencies.lock` baseline snapshot is 1.6.1, 1.2.11,
1.15.18, 1.44.1, and 2.1.1 respectively, as observed from the upstream project
pages on 2026-09-01. These baselines are documentation and fake-surface
compatibility authority, not a claim that live upstream packages ran in the
offline gate. The lock records `OFFLINE_FAKE_SURFACE_ONLY` until a separately
authorized dependency-prefetch packet can execute real package matrices.

The bounded adapters expose only LangChain runnable `invoke`/`ainvoke`,
LangGraph graph `invoke`/`ainvoke`, CrewAI crew `kickoff`/`kickoff_async`,
Semantic Kernel `invoke`/`invoke_prompt`, and MCP client `call_tool`. MCP defaults
to the SDK-004 `2026-07-28` revision and admits only its explicit
`2025-11-25` compatibility mode. A sixth, dependency-free vector adapter wraps
a caller-supplied synchronous or asynchronous search callable and deliberately
does not select or install a vector vendor.

Every wrapper uses fixed `harness.integration.*` operation names, delegates only
when the caller invokes it, preserves return values and exceptions, and sends
records only to an explicit SDK-002 sink. Arguments, prompts, messages, results,
exception text, credentials, framework state, and tenant identity from
framework metadata are never captured. The upstream baselines and extension
shapes are grounded in the official LangChain/LangGraph documentation,
CrewAI event documentation, Microsoft Semantic Kernel filter documentation,
and the official MCP Python SDK release line; their URLs are recorded in the
lock rather than fetched during build or runtime.

### SDK-006 guardrail contract

SDK-006 owns a deterministic in-process SDK contract and the conformance
vectors later consumed by the downstream trust guardrail packet; it does not claim a guardrail schema in
the current `contracts.lock.json`, create a deployable service, or add a network
transport. Python exposes `planeon_harness.guardrail`. TypeScript exposes the
same contract from `@planeon/harness-sdk/guardrail`; source, committed
JavaScript, declarations, export map, and fixtures move together while the
generator-owned package root remains unchanged.

A closed `GuardrailProfile` identifies one of `INPUT`, `OUTPUT`, `RUNTIME`,
or `STREAMING`, an explicit `FAIL_CLOSED` or `FAIL_OPEN` mode, a 1 through
1,048,576 UTF-8-byte content limit, and an ordered set of local detector IDs.
The client is transport-neutral and synchronous in this packet. It accepts
caller-supplied detectors only, performs no detector call during construction,
and rejects missing or duplicate registrations before content is evaluated.
External moderation APIs, remote detectors, model downloads, provider SDKs,
API keys, evidence persistence, and automatic telemetry are excluded.

Each detector returns a stable content-free reason, one of `ALLOW`, `DENY`,
`REDACT`, or `QUARANTINE`, and Unicode-scalar redaction ranges only for
`REDACT`. Ranges must be ordered, non-overlapping, and in bounds. The client
combines ranges across detectors by sorted union, merges overlaps and adjacency,
and substitutes the exact token `[REDACTED]`. Raw input is never a result field;
sanitized content exists only for a `REDACT` outcome.

Oversized input is denied before a detector runs. Detector exceptions and
malformed findings never escape with their type, message, or value.
`FAIL_CLOSED` stops on the first such failure with `ERROR_FAIL_CLOSED`.
`FAIL_OPEN` remains explicit: it records only failed detector IDs, marks the
result degraded, continues evaluation, and applies the closed precedence
`DENY > QUARANTINE > REDACT > ERROR_FAIL_OPEN > ALLOW`. A concrete winning
finding supplies the first profile-ordered reason at that precedence.

Streaming uses the same evaluator over the complete bounded cumulative buffer
after every non-empty chunk, making split matches observable without unbounded
retention. `DENY`, `QUARANTINE`, and `ERROR_FAIL_CLOSED` clear and terminate
the stream. `finish` returns the latest evaluation, evaluates one empty buffer
only when no chunk was pushed, clears content, and closes the stream. Terminal
and finished calls fail with distinct content-free codes.

Shared fixtures cover every stage, outcome, failure mode, precedence branch,
UTF-8 limit, Unicode redaction case, detector outage/malformed result, and
streaming boundary. Python and TypeScript serialize the closed result shape as
byte-identical sorted compact UTF-8 JSON. Protected fixture sentinels must be
absent from expected results, errors, telemetry, and captured output.

### SDK-007 compatibility contract

SDK-007 creates a separate `planeon-prometa-compat` 0.1.0 wheel that depends
exactly on `planeon-harness-sdk==0.1.0`. It never modifies or vendors the
canonical distribution. Its approved surface is deliberately closed to five
module mappings:

| Compatibility import | Canonical import |
|---|---|
| `prometa` | `planeon_harness` |
| `prometa.guardrail` | `planeon_harness.guardrail` |
| `prometa.integrations` | `planeon_harness.integrations` |
| `prometa.protocols` | `planeon_harness.protocols` |
| `prometa.runtime` | `planeon_harness.runtime` |

Each compatibility module exports every and only its canonical target's
`__all__` names, and each value is the same object rather than a wrapper or
copy. The root exposes the canonical `__version__`. Importing `prometa` emits
one `DeprecationWarning`: `The prometa import is deprecated; use
planeon_harness. It is supported only through planeon-harness-sdk v1 and will
be removed in v2.` Submodules add no warnings. An unknown module or attribute
is not synthesized.

This is a newly approved migration alias, not evidence about an unobserved
legacy repository. Implementation cannot mount or inspect a warm source, infer
additional legacy modules, or claim compatibility for any historical private
API. `NOT_CLAIMED` remains the explicit matrix state for every such surface.
New platform code imports `planeon_harness` directly; only migrating external
callers may install the compatibility wheel.

`python/compat-pyproject.toml` is a closed, dependency-free build manifest. A
packet-owned backend builds only the pure-Python compatibility wheel, fixes
timestamps, modes, ordering, metadata, license, and `RECORD`, and compares two
isolated builds byte for byte. Default verification prints the wheel digest and
negative evidence states but retains and publishes nothing. An explicit
caller-owned output directory may receive one already-verified wheel for a
later offline release assembly; SDK-007 itself does not publish it.

Wheel-isolated subprocess tests cover the five imports, exact `__all__`, object
identity, warning count/message, absent unknown modules, optional-framework
non-loading, closed wheel membership, metadata, and record hashes. A separate
subprocess rejects every `prometa` import while importing all five canonical
surfaces, proving the dependency remains compatibility-to-canonical only.
The packet adds `compat-vectors` and a cumulative `build-reproducible` handler
through `ci/targets/sdk-007.json`; it does not edit the bootstrap Makefile,
dispatcher, canonical build backend, generated roots, or `PORTING.yaml`.

For every later release before v2, the canonical and compatibility versions,
exact dependency, vectors, and compatibility matrix move atomically. Version
2 removes the alias package only after the migration report. Rollback withdraws
the optional wheel without changing canonical SDK artifacts.

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
