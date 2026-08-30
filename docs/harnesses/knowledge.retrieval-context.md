# Harness Specification: `knowledge.retrieval-context`

## Contract

| Field | Value |
|---|---|
| Plane | Knowledge |
| Owning repository | `mas-harness-knowledge-plane` |
| Warm source | `data-source-harness@858281f4b845ffacfe05cdb2c40a402c237d4c54` |
| API version | `harness.planeon.ai/v1alpha1` |

## Capabilities and non-goals

This harness creates versioned retrieval indexes from accepted data batches, performs tenant- and policy-filtered lexical/vector/hybrid retrieval, reranks locally, assembles bounded context, and returns source citations with provenance and freshness metadata.

It does not own source ingestion, edit source data, store long-term user memory, persist orchestration checkpoints, or permit uncited model-generated statements to masquerade as retrieved evidence.

## Owner and deployables

- `retrieval-service`: query validation, policy filters, hybrid search, reranking, context assembly, and citation response.
- `index-worker`: builds immutable index generations from accepted batch/domain digests.
- Optional reranker image: local cross-encoder, selected separately.

## Dependencies, conflicts, and ordering

- Required: `runtime.infrastructure`, `knowledge.domain-semantic`, `knowledge.data-integration`, `trust.security-safety`, `trust.observability-finops`.
- Optional: `runtime.model-inference` for embeddings/reranking, `trust.evaluation-assurance`, `runtime.ai-gateway`.
- Conflicts:
  - Index generation references unaccepted or quarantined data.
  - Embedding model lacks custody/license approval or is not available offline.
  - Filter schema cannot enforce tenant/classification restrictions.
  - A profile requests memory write through retrieval APIs.

Index build follows accepted domain and data digests; activation precedes consumer route promotion.

## Provider implementations

- `planeon.postgres-hybrid`: baseline PostgreSQL full-text search plus pgvector; lexical-only mode does not require model inference.
- `planeon.local-cross-encoder`: optional local reranking provider using an approved model artifact.
- `planeon.qdrant`: contract-only, non-installable vector-store guidance; an active selector is rejected as `PROVIDER_UNAVAILABLE`.

PostgreSQL hybrid is the only selectable store in this release. If its certified
capacity/latency envelope is insufficient, compilation reports an unsupported
requirement instead of selecting Qdrant.

## Configuration and runtime boundaries

```yaml
index:
  id: string
  domainDigest: sha256:...
  sourceBatchSelectors: []
  strategy: lexical | vector | hybrid
  chunking:
    method: semantic-boundary | fixed
    maxTokens: integer
    overlapTokens: integer
  embeddingRouteId: string-or-null
  dimensions: integer-or-null
  metadataAllowlist: [field]
query:
  topK: integer
  candidateK: integer
  maxContextTokens: integer
  rerankerRouteId: string-or-null
  minimumScore: decimal-string
citations:
  required: true
  includeProvenance: true
```

- Secrets: no baseline secrets; optional store credentials are references.
- RBAC: no Kubernetes API access. Roles are `retrieval:index-admin` and `retrieval:query`.
- Network: index worker reaches accepted batch storage, domain service, selected embedding route, index store, policy, and OTel. Query service reaches index, policy, optional reranker, and OTel only.
- Storage: each tenant/index generation uses a separate schema/collection. Chunks contain source object IDs and provenance digests, not undisclosed credential/source metadata. Runtime memory/checkpoints are excluded.

## APIs, events, and state

```text
POST /knowledge/v1/indexes
POST /knowledge/v1/indexes/{id}:build
POST /knowledge/v1/indexes/{id}/generations/{generation}:activate
GET  /knowledge/v1/indexes/{id}
POST /knowledge/v1/retrieve
POST /knowledge/v1/context:assemble
```

Index generation states: `DECLARED → BUILDING → VALIDATING → READY → ACTIVE`; alternatives `FAILED`, `STALE`, `SUPERSEDED`, `REVOKED`.

Emitted:

- `retrieval.index.build.requested.v1`
- `retrieval.index.ready.v1`
- `retrieval.index.activated.v1`
- `retrieval.index.stale.v1`
- `retrieval.query.completed.v1`

Consumed: `data.batch.committed.v1`, `data.source.degraded.v1`, `domain.version.superseded.v1`, `model.route.rejected.v1`.

Query events contain counts, filters, scores, latency, and digests—not query text or retrieved content unless an evidence plan explicitly permits classified payload storage.

## Failures, retry, and rollback

- Index builds write a new immutable generation and activate atomically only after validation.
- Build retries from a content-addressed checkpoint; corrupt or changed batch digests fail closed.
- Query failure never broadens filters or falls back across tenant/classification boundaries.
- Vector-provider outage may use lexical fallback only when the profile declares it and the response marks `retrievalMode` accordingly.
- Reranker failure may return pre-reranked results only if its policy marks reranking optional.
- Rollback reactivates a previously validated generation; deletion follows retention and active-reference checks.
- Source/domain supersession marks affected generations `STALE` but does not mutate their contents.

## Evidence and readiness gates

- Accepted source batch and active domain digests.
- Chunk coverage, duplicate rate, orphan citation rate, and sensitive-field handling.
- Tenant/classification filter enforcement.
- Citation resolution from chunk to source and provenance.
- Retrieval quality set with recall, precision/nDCG, citation correctness, and freshness.
- Embedding/reranker custody, license, and local availability when selected.
- Index rebuild determinism or documented acceptable nondeterminism bounds.

Production readiness requires zero cross-tenant/filter violations and current quality/freshness evidence.

## Profile behavior

- `minimal-local`: PostgreSQL full-text or hybrid, one active generation, no reranker by default.
- `enterprise`: hybrid retrieval, replicated query service, local reranking, generation retention and quality gates.
- `airgap-enclave`: all embedding/reranker weights imported; no remote embedding API; offline citations remain resolvable.

## Tests

- Independent clean-room parity against pre-recorded, digest-pinned vectors: query plans, context assembly, citations, source routing, and semantic mapping fixtures; no warm checkout access.
- Unit: chunking, filters, scoring merge, token budget, citation construction, staleness propagation.
- Contract: APIs/events and model/data/domain dependencies.
- Security: tenant/filter bypass, SQL/filter injection, malicious metadata, payload logging.
- Quality: white-goods golden query set including ambiguous, stale, absent, and conflicting evidence.
- Failure: interrupted build, corrupt batch, model outage, store outage, atomic activation/rollback.
- Air gap: index build and query with egress denied.

## Sol-high implementation packets

1. `KN-001-foundation`: shared knowledge kernel, RLS/inbox/outbox, privacy-safe references, images/charts, and dependency mocks.
2. `KN-RET-001`: index generations, PostgreSQL FTS/pgvector, optional local embeddings/reranking, hybrid ranking, tenant/classification filters, bounded context, citations/provenance, source/domain invalidation, quality gates, and rollback.
3. `KN-002-security-resilience`: tenant/index isolation, malicious content/metadata, stale-index behavior, model/store outages, atomic recovery, and offline operation.

Each packet keeps retrieval storage and APIs independent from memory and orchestration state.
