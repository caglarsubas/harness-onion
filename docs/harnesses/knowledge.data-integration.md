# Harness Specification: `knowledge.data-integration`

## Contract

| Field | Value |
|---|---|
| Plane | Knowledge |
| Owning repository | `mas-harness-knowledge-plane` |
| Warm source | `data-source-harness@858281f4b845ffacfe05cdb2c40a402c237d4c54` |
| API version | `harness.planeon.ai/v1alpha1` |

## Capabilities and non-goals

This harness declares tenant data sources, validates connectivity and schemas, performs bounded read ingestion, normalizes records against the active domain model, records lineage/provenance, measures quality/completeness/freshness, and publishes immutable batches for downstream indexing and assurance.

It does not perform arbitrary source mutations, execute tools, own retrieval indexes, write long-term memory, infer that incomplete data are acceptable, or store credentials in source definitions. Write-capable integration is delegated through `execution.tool-skill-sandbox` with governance and receipts.

## Owner and deployables

- `connector-controller`: source declarations, connector lifecycle, schedules, checkpoints, and readiness aggregation.
- `ingest-worker`: ephemeral/bounded worker for extract, decode, map, validate, persist, and provenance.
- Connector images: independently packaged HTTP/OpenAPI, JDBC/PostgreSQL, filesystem/object, and event-stream providers.

Only selected connector images appear in a tenant bundle.
SFTP is contract-only, non-installable comparative guidance in this release and
cannot be selected into a bundle.

## Dependencies, conflicts, and ordering

- Required: `runtime.infrastructure`, `knowledge.domain-semantic`, `trust.security-safety`, `trust.observability-finops`.
- Required for production acceptance: `trust.governance-agentops`.
- Optional: `knowledge.retrieval-context`, `execution.ml-decision`, `trust.evaluation-assurance`.
- Conflicts:
  - Source mapping targets a non-active or mismatched domain digest.
  - Connector requests mutation/write capability.
  - Offline profile contains a remote endpoint that is not reachable inside the enclave.
  - Source retention or residency conflicts with the tenant evidence plan.
  - Connector image/license is not redistributable for the selected distribution.

Ordering: domain publication, identity/policy, connector validation, sampling/readiness, owner approval, then production ingestion.

## Provider implementations

- `planeon.connector.http`: bounded HTTP/OpenAPI reads with allowlisted hosts and pagination.
- `planeon.connector.jdbc`: read-only JDBC/PostgreSQL queries using prepared statements and source-side limits.
- `planeon.connector.file`: mounted filesystem and imported object batches.
- `planeon.connector.sftp`: contract-only, non-installable guidance for allowlisted reads and host-key pinning; an active selector is rejected as `PROVIDER_UNAVAILABLE`.
- `planeon.connector.events`: tenant-local Kafka/NATS-compatible subscriptions.

The connector contracts, worker pipeline, provenance, freshness, white-goods
fixtures, and certification tests are independent clean-room targets derived
only from released contracts and pre-recorded, digest-pinned observations;
implementation cannot access, copy, adapt, translate, or derive code from a
warm checkout. HMAC production signing, fused state models, and the old
canonical namespace are not retained.

## Configuration and runtime boundaries

```yaml
source:
  id: string
  connectorProvider: string
  endpointRef: string
  credentialSecretRef: {name: string, keyMapping: {}}
  classification: public | internal | confidential | restricted
  residency: [string]
  owner: subject-id
  accessMode: read-only
schema:
  expectedSchemaDigest: sha256:...
  domainMappingDigest: sha256:...
ingestion:
  mode: snapshot | incremental | stream
  schedule: cron-or-disabled
  checkpointPolicy: source-specific
  maxRecordsPerBatch: integer
  maxBytesPerBatch: integer
readiness:
  completenessMin: decimal-string
  freshnessMaxSeconds: integer
  provenanceCoverageMin: decimal-string
  duplicateRateMax: decimal-string
```

- Secrets: referenced Kubernetes Secret paths; mounted only into the selected worker and never returned by APIs.
- RBAC: controller reads owned source CRs/config; workers have no Kubernetes API access and use connector-specific service accounts.
- Network: each worker receives an egress policy containing only source host/port, DNS, policy, storage, and OTel. Connector input is never converted into an unrestricted URL.
- Storage: source metadata/checkpoints/provenance live in data-integration-owned knowledge tables. Raw/normalized batches use tenant PVC or declared tenant-owned S3-compatible storage. Batches are content addressed and immutable.

## APIs, events, and state

```text
POST /knowledge/v1/sources
GET  /knowledge/v1/sources/{id}
POST /knowledge/v1/sources/{id}:validate
POST /knowledge/v1/sources/{id}:sample
POST /knowledge/v1/sources/{id}:activate
POST /knowledge/v1/sources/{id}:ingest
GET  /knowledge/v1/sources/{id}/readiness
GET  /knowledge/v1/batches/{id}
GET  /knowledge/v1/batches/{id}/provenance
```

Source states: `DECLARED → VALIDATING → SAMPLED → READY_FOR_APPROVAL → ACTIVE`; alternatives `INVALID`, `DEGRADED`, `DISABLED`, `REVOKED`.

Batch states: `PLANNED → READING → DECODING → MAPPING → VALIDATING → COMMITTED`; alternatives `RETRYABLE_FAILED`, `FAILED`, `QUARANTINED`.

Emitted:

- `data.source.validated.v1`
- `data.readiness.assessed.v1`
- `data.batch.committed.v1`
- `data.batch.quarantined.v1`
- `data.source.degraded.v1`

Consumed: `domain.version.published.v1`, `approval.decided.v1`, `policy.bundle.activated.v1`.

## Failures, retry, and rollback

- Connectivity and sampling failures do not activate a source.
- Snapshot/incremental batches commit atomically after validation. Partial output remains staging and is never advertised.
- Checkpoints advance only after batch commit. Duplicate source records are handled through declared stable record IDs and batch digests.
- Reads retry three times with jitter when the connector class declares the error transient. Authentication, schema, policy, and mapping failures do not retry automatically.
- Stream consumers use inbox/checkpoint semantics and tolerate duplicate delivery.
- Schema drift creates a new readiness finding and pauses ingestion when classified breaking.
- Rollback repoints consumers to the last accepted batch/index input; source systems are never modified.

## Evidence and readiness gates

- Named owner, classification, residency, retention, and lawful/approved purpose.
- Credential and connectivity validation without secret disclosure.
- Expected/observed schema diff.
- Completeness, freshness, duplicate, null, type, sensitive-field, and provenance coverage measurements.
- Domain mapping coverage and unresolved-term report.
- Source/batch lineage from origin through normalized object.
- Read-only enforcement and egress-policy test.
- Sample acceptance by the data owner.

Production activation requires all pack-mandated readiness thresholds; warnings require explicit, expiring governance waiver.

## Profile behavior

- `minimal-local`: mounted files and local PostgreSQL/HTTP sources, manual ingestion, local PVC.
- `enterprise`: multiple connectors, scheduled/incremental workers, HA metadata store, source-specific quotas.
- `airgap-enclave`: only enclave-local endpoints or imported files/objects; selected connector images, drivers, and certificates are vendored.

## Tests

- Independent clean-room parity against pre-recorded, digest-pinned vectors: connector profiles, batches, provenance, freshness, coverage, mapping, and air-gap fixtures; no warm checkout access.
- Unit: pagination, checkpoints, schema diff, quality metrics, provenance graph, stable IDs.
- Contract: source/batch APIs, connector SDK, CloudEvents, domain mapping.
- Security: SSRF, SQL injection, path traversal, archive bombs, secret/log redaction, and write attempts. SFTP host-key-mismatch cases are retained only as non-installable comparative vectors.
- Failure: source timeout, restart after read before commit, duplicate stream event, schema drift, storage exhaustion.
- Industry: white-goods API/database/file/event sources with clean, incomplete, stale, duplicate, and unmapped variants.

## Sol-high implementation packets

1. `KN-001-foundation`: common service kernel, tenant roles/RLS, inbox/outbox, privacy-safe references, images/charts, and dependency mocks.
2. `KN-DATA-001`: clean-room connector/decoder/batch implementation, source lifecycle, controller leases/checkpoints, file/HTTP/PostgreSQL/event providers, read-only credentials, and hostile-input handling.
3. `KN-DATA-002`: atomic batches, retry/dead-letter, provenance graph, completeness/freshness/coverage/classification findings, owner approval, and white-goods source fixtures.
4. `KN-002-security-resilience`: connector SSRF/egress, tenant/store isolation, malicious files/documents, duplicate events, source/storage outages, and air-gap operation.

Each packet implements one bounded clean-room source slice and preserves raw, retrieval, memory, and runtime state separation.
