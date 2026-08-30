# Repository Plan: `mas-harness-knowledge-plane`

## Purpose and boundaries

This repository owns four separately installable harnesses: `knowledge.domain-semantic`, `knowledge.data-integration`, `knowledge.retrieval-context`, and `knowledge.memory-state`. It provides domain validation, connectors/ingestion/provenance, retrieval/context assembly, and governed memory while maintaining strict store and API boundaries.

Non-goals:

- No model hosting, workflow scheduling, arbitrary tool execution, policy authority, control-plane questionnaire, or Kubernetes reconciliation.
- Retrieval indexes, persistent memory, source/provenance data, and runtime checkpoints are never fused.
- Connectors do not mutate sources; write actions belong to execution/tool governance.

## Repository structure and exact tree

This tree projects the current task-packet `allowedPaths`. Directory entries do not authorize edits beyond the packet executed in a coding run.

```text
mas-harness-knowledge-plane/
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
├── pyproject.toml
├── uv.lock
├── ci/
├── contract-mocks/
├── src/planeon_knowledge/
│   ├── common/
│   ├── domain/
│   ├── ingestion/
│   │   ├── connectors/
│   │   ├── classification.py
│   │   ├── coverage.py
│   │   ├── decoder.py
│   │   ├── evidence.py
│   │   ├── freshness.py
│   │   ├── leases.py
│   │   └── provenance.py
│   ├── retrieval/
│   └── memory/
├── services/
│   ├── domain-service/
│   ├── connector-controller/
│   ├── ingest-worker/
│   ├── retrieval-service/
│   ├── index-worker/
│   └── memory-service/
├── migrations/
│   ├── domain/
│   ├── ingestion/readiness/
│   ├── retrieval/
│   └── memory/
├── deploy/helm/
│   ├── domain-service/
│   ├── connector-controller/
│   ├── ingest-worker/
│   ├── retrieval-service/
│   ├── index-worker/
│   └── memory-service/
├── fixtures/{attacks,connectors,domain,memory,readiness,retrieval}/
├── scripts/run_failure_campaign.py
├── docs/runbooks/
└── tests/{airgap,common,connectors,domain,memory,readiness,resilience,retrieval,security}/
```

## Deployables and toolchain

- Services: `domain-service`, `connector-controller`, `ingest-worker`, `retrieval-service`, `index-worker`, and `memory-service`; each has a separate non-root image/chart/service account.
- Python 3.12.14, FastAPI, Pydantic v2, psycopg 3, PostgreSQL/pgvector, RDFLib, pySHACL, jsonschema, HTTPX, cryptography, and OpenTelemetry; exact versions frozen in `uv.lock`.
- Baseline connectors are local file, allowlisted HTTP, PostgreSQL read-only, and deterministic event fixture. New connectors use the documented SDK and separate module manifest.

## Owned APIs, events, and stores

```text
/knowledge/v1/domains
/knowledge/v1/domains/{id}/versions
/knowledge/v1/mappings:validate
/knowledge/v1/sources
/knowledge/v1/sources/{id}:assess
/knowledge/v1/retrieve
/knowledge/v1/context:assemble
/knowledge/v1/indexes
/knowledge/v1/memory:read
/knowledge/v1/memory:write
/knowledge/v1/memory:delete
```

Store ownership uses one tenant database with separate owners/RLS schemas:

- `domain`: ontology versions, semantic mappings, validation results.
- `ingestion`: source declarations, connector leases, batches, provenance, freshness, coverage, classification findings.
- `retrieval`: chunks, citations, index versions, pgvector embeddings; every index is tenant and source-version scoped.
- `memory`: memory entries, consent/purpose, TTL, deletion tombstones, and redaction receipts.

No service writes another schema. Runtime checkpoints are explicitly forbidden. Binary source/evidence objects use tenant PVC or tenant-supplied S3-compatible storage through references.

Emits source/batch/provenance/freshness/index/memory/evidence events. Consumes accepted domain/data declarations, policy decisions, deletion requests, and local embedding/rerank responses. Events carry IDs/digests, not source payloads.

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

- Upstream: contracts, SDK, trust policy/guardrail/evidence APIs, PostgreSQL/pgvector, OTel, tenant source endpoints, and model plane only for selected local embeddings/reranking.
- Downstream: runtime context assembly, execution workflows/tools, industry/conformance evidence.
- Trust/OPA loss fails closed for source access and memory writes/deletes. Model loss pauses indexing requiring embeddings but does not corrupt existing indexes.

## Warm-source mapping

Public source provenance is recorded only in `architecture/reuse-map.yaml`, `architecture/reuse-path-index.yaml`, and packet `sourceReuse` entries. Non-public planning inputs have already been distilled into independent public contracts and acceptance criteria; their repository names, commits, paths, and object IDs are deliberately omitted. They are not mounted or required during implementation. No source is copy-authorized.

## PR packets

1. `KN-001-foundation`: common service kernel, tenant DB roles/RLS, outbox/inbox, source-reference privacy, images/charts, and contract mocks.
2. `KN-DOM-001`: ontology versions, SHACL validation, semantic mapping, domain evidence, and white-goods ontology parity.
3. `KN-DATA-001`: connector controller/leases, file/HTTP/PostgreSQL/event connectors, decoder/batch contracts, and read-only credentials.
4. `KN-DATA-002`: provenance graph, freshness/coverage/classification assessments, readiness evidence, retry/dead-letter, and white-goods source fixtures.
5. `KN-RET-001`: chunk/index lifecycle, PostgreSQL FTS/pgvector, local embeddings/reranking, retrieval citations, context limits, and source-version invalidation.
6. `KN-MEM-001`: explicit purpose/consent write, read policy, TTL, deletion/tombstones, redaction, and proof that memory is not retrieval/runtime state.
7. `KN-002-security-resilience`: tenant/store isolation, malicious documents, connector SSRF/egress, stale indexes, outage recovery, and air-gap operation.

## Testing, verification, and acceptance

The `KN-001` bootstrap packet declares
`prefetchCommands: [["make","prefetch"]]` and ordered
`offlineAcceptanceCommands:
[["make","common-contract"],["make","security"]]`.
Later packets add lint, type, coverage, parity, contract, local PostgreSQL,
white-goods, zero-bill, and reproducibility checks as direct argv arrays. The
executor supplies the hash-pinned packet through `HARNESS_TASK_PACKET` and
invokes only `offlineExecution.wrapperArgv: ["./ci/verify-offline.sh"]` for the
complete ordered list.

Acceptance: white-goods mock sources ingest read-only, produce complete provenance/freshness/coverage, validate domain mappings, build a versioned index, return cited tenant-isolated context, and store/delete governed memory independently. Cross-schema/tenant access, SSRF, prompt injection metadata, stale-citation use, and secret leakage are denied. All services operate with egress restricted to declared tenant sources/local dependencies.

## Release and rollback

- Each harness/deployable is an independent module release with compatible contracts and migration range.
- Index builds are create-then-swap; failed builds retain previous ready index. Ontology/mapping versions are immutable.
- DB migrations use expand/contract. Rollback selects prior images and index/version pointers; source data, memory, tombstones, and provenance are retained. Destructive deletion requires an explicit signed request and receipt.

## Zero-bill rules

- No hosted embeddings/vector DB/object store, crawling SaaS, remote telemetry, automatic connector discovery, or runtime downloads.
- HTTP connectors are allowlisted tenant endpoints; cloud metadata/link-local/private-network SSRF rules are enforced unless an exact tenant destination is approved.
- Self-hosted offline CI only; no GitHub storage/cache/Packages, cloud databases, scheduled ingestion, or paid evaluation APIs.
