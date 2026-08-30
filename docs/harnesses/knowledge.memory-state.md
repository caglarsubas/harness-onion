# Harness Specification: `knowledge.memory-state`

## Contract

| Field | Value |
|---|---|
| Plane | Knowledge |
| Owning repository | `mas-harness-knowledge-plane` |
| Public warm source | `data-source-harness`; non-public planning input metadata omitted |
| API version | `harness.planeon.ai/v1alpha1` |

## Capabilities and non-goals

This harness provides explicitly governed persistent memory for agents and users: typed memory classes, consent-aware writes, tenant/subject scopes, retention and TTL, recall filters, provenance, correction, export, deletion, and optional local semantic search.

It does not store durable workflow checkpoints, source-of-truth business data, retrieval corpus chunks, caches, secrets, hidden reasoning, or arbitrary interaction transcripts. Memory is never enabled implicitly because an orchestration framework supports it.

## Owner and deployables

- `memory-service`: policy-gated read/write/search/correct/delete/export API and lifecycle worker.
- `memory-expiry-worker`: optional independently scalable expiry and deletion processor; embedded in `memory-service` for minimal profiles.

## Dependencies, conflicts, and ordering

- Required: `runtime.infrastructure`, `trust.security-safety`, `trust.governance-agentops`, `trust.observability-finops`.
- Optional: `runtime.model-inference` for embeddings, `knowledge.domain-semantic`, `trust.evaluation-assurance`.
- Conflicts:
  - Memory without a declared purpose, owner, subject scope, retention, and deletion policy.
  - Restricted data in shared `pool` mode when the pack requires silo isolation.
  - Cross-tenant or cross-subject recall not backed by an explicit policy decision.
  - Embedding provider that sends content outside the tenant boundary.
  - Workflow checkpoints or retrieval chunks written through the memory API.

Memory is enabled only after governance policy and data-classification readiness pass.

## Provider implementations

- `planeon.memory.postgres`: baseline typed records, PostgreSQL full-text, audit receipts.
- `planeon.memory.pgvector`: optional semantic recall using a selected local embedding route.

The baseline does not require Redis or an external vector database.

## Configuration and runtime boundaries

```yaml
classes:
  - id: preference | episodic-summary | semantic-fact | tenant-custom
    allowedScopes: [tenant, user, agent, workflow-family]
    allowedClassifications: [internal]
    purpose: string
    ttlSeconds: integer
    maximumTtlSeconds: integer
    consentRequired: boolean
    approvalRequired: boolean
    semanticIndex: enabled | disabled
writePolicy:
  requireProvenance: true
  allowModelProposed: true
  modelProposedRequiresConfirmation: true
deletion:
  graceSeconds: integer
  tombstoneRetentionSeconds: integer
```

- Secrets: database/embedding credentials are references; memory payloads never enter secrets.
- RBAC: application scopes `memory:read`, `memory:propose`, `memory:write`, `memory:correct`, `memory:delete`, and `memory:export` are separate.
- Network: ingress from approved orchestration/experience services; egress to policy, PostgreSQL, optional local embeddings, and OTel.
- Storage: memory-owned PostgreSQL tables and optional pgvector columns. Row tenant scope and subject scope are mandatory, with RLS defense in depth. Tombstones contain identifiers/digests only.

## APIs, events, and state

```text
POST /knowledge/v1/memory:propose
POST /knowledge/v1/memory:write
POST /knowledge/v1/memory:read
POST /knowledge/v1/memory:search
POST /knowledge/v1/memory/{id}:correct
POST /knowledge/v1/memory/{id}:delete
POST /knowledge/v1/memory:export
GET  /knowledge/v1/memory/{id}/receipt
```

Memory states: `PROPOSED → ACTIVE`; alternatives `REJECTED`, `QUARANTINED`, `EXPIRED`, `DELETION_PENDING`, `DELETED`, `SUPERSEDED`.

Emitted:

- `memory.write.proposed.v1`
- `memory.record.activated.v1`
- `memory.record.corrected.v1`
- `memory.record.deleted.v1`
- `memory.policy.denied.v1`

Consumed: `approval.decided.v1`, `policy.bundle.activated.v1`, `subject.deletion.requested.v1`, and embedding route revocation.

Events never include memory content.

## Failures, retry, and rollback

- Writes require an idempotency key and provenance; policy and consent failures deny before storage.
- Model-proposed memory remains `PROPOSED` until the configured confirmation/approval.
- Database loss rejects all state-changing operations; reads return a stable unavailable reason, never fabricated empty memory.
- Embedding failure may store a non-semantic record only when the class permits it; otherwise the write remains retryable and uncommitted.
- Correction creates a new immutable version and supersedes the old record.
- Deletion first blocks recall, then removes payload/vector after grace; retries are idempotent.
- Backup restore must preserve deletions using a deletion ledger newer than the restored snapshot.
- Rollback changes service/schema version but must not resurrect expired/deleted memory.

## Evidence and readiness gates

- Purpose, owner, classification, consent, TTL, maximum retention, and deletion behavior for each class.
- Policy decisions for cross-scope reads and write/correction/delete operations.
- Provenance and confirmation receipt for model-proposed memories.
- RLS and application-layer tenant/subject isolation.
- Expiry, correction, export, deletion, backup/restore, and non-resurrection tests.
- Content/log/event redaction inspection.
- Semantic retrieval quality and embedding custody when enabled.

Production readiness requires verified deletion and isolation, not merely successful writes/reads.

## Profile behavior

- `minimal-local`: memory disabled by default; when selected, PostgreSQL records with short TTL and no semantic index.
- `enterprise`: approved typed classes, RLS, semantic recall, confirmation workflow, expiry worker, export/deletion.
- `airgap-enclave`: local embeddings only, no external identity/data processor, all retention work continues disconnected.

## Tests

- Unit: class validation, TTL, scopes, consent, correction chains, tombstones.
- Contract: SDK/runtime APIs, CloudEvents, policy and approval integration.
- Security: tenant/subject crossover, ID guessing, filter injection, payload leakage, consent bypass.
- Lifecycle: propose/confirm, expire, correct, delete, retry, export, restore without resurrection.
- Failure: DB outage, embedding outage, crash during deletion, duplicate deletion request.
- Separation: reject checkpoint, retrieval-chunk, source-record, and secret payload types.

## Sol-high implementation packets

1. `KN-001-foundation`: shared knowledge service kernel, separate tenant roles/RLS, inbox/outbox, privacy-safe references, images/charts, and mocks.
2. `KN-MEM-001`: typed classes/purpose/consent, policy-gated propose/read/write/correct, PostgreSQL/optional pgvector, TTL, immutable versions, deletion/tombstones/export, local embeddings, redaction, and proof of state separation.
3. `KN-002-security-resilience`: tenant/subject/store isolation, payload attacks, DB/embedding outage, crash-safe deletion, backup/restore non-resurrection, and air-gap operation.

Packets cannot reuse orchestration checkpoint or retrieval index tables and cannot enable memory by default in existing profiles.
