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
- `KN-001` starts from the empty public repository commit `f3a3463d2fe04d4b17dc3abbebc6b3375bd6d890` and bootstraps source-only, health-only shells for exact Python 3.12.14 with no third-party dependency. It does not build an image, connect to PostgreSQL, or deploy a chart.
- The target stack for later packets remains FastAPI, Pydantic v2, psycopg 3, PostgreSQL/pgvector, RDFLib, pySHACL, jsonschema, HTTPX, cryptography, and OpenTelemetry. A later packet must admit and freeze each exact dependency before use; their mention here is not installation or execution authority for `KN-001`.
- Baseline connectors are local file, allowlisted HTTP, PostgreSQL read-only, and deterministic event fixture. New connectors use the documented SDK and separate module manifest.

### `KN-001` foundation boundary

The bootstrap produces only common canonical JSON/digest/error primitives,
server-admitted `TenantIdentity`, metadata-only `SourceReference`, `InboxRecord`
and `OutboxRecord`, dependency health, six immutable service descriptors, six
health-only ASGI adapters, four additive SQL source contracts, local synthetic
contract mocks, six source-only Containerfiles, and six disabled-by-default Helm
charts. It does not implement any endpoint listed below under “Owned APIs”; those
are allocated to later behavior packets.

Readiness is fail-closed. Each service requires its local identity-admission,
policy, contract-mock, and owned-store probes to be `READY`. Optional telemetry
may be `DEGRADED`, but that state never authorizes work. Unknown routes, methods,
bodies, query strings, caller identity, missing or malformed probes, timeouts,
and probe exceptions return bounded metadata-only failures and never trigger
network discovery or retry.

### `KN-DOM-001` domain-service boundary

`KN-DOM-001` preserves the dependency-free KN-001 root package and root lock.
RDFLib 7.6.0, pySHACL 0.40.1, and their exact eight-package runtime closure are
declared and digest/license locked only in `services/domain-service/`; acceptance
uses the preinstalled root-owned IND-WG-001 semantic toolchain without package
resolution. This prevents a later harness dependency from silently changing the
foundation closure or another service image.

Domain packages and semantic mappings are immutable digest-bound metadata.
Graph/shapes bytes are supplied transiently by an injected local exact-digest
provider and are never placed in SQL, events, evidence, errors, or logs. Only
bounded Turtle and inline-context JSON-LD are admitted. The implementation
rejects remote contexts/imports, arbitrary network/file IRIs, RDF/XML, archives,
SPARQL/JavaScript/rule-based SHACL, over-limit graphs, and any engine mode other
than the closed local RDFLib/pySHACL profile.

Version and mapping state histories are append-only. Publication requires an
already verified, digest-bound approval attestation plus an exact unexpired
policy permit. Activation and compatible rollback atomically append revisions,
evidence, and an outbox event while switching one tenant-scoped active pointer;
failure leaves the prior pointer unchanged. A policy allow, fixture, test, or
generated output is never owner approval. Runtime PostgreSQL, image, and chart
execution remain `NOT_RUN_ENV_UNAVAILABLE` for this packet.

## Owned APIs, events, and stores

The following are repository-level API ownership assignments, not `KN-001`
deliverables. Their respective later packets must define request/response,
identity, policy, idempotency, state-transition, and failure contracts before
implementation.

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

`KN-001` creates no binary store and no business table. It provides identical
`source_reference`, `inbox_event`, and `outbox_event` foundation tables inside
each of the four schemas, with separate NOLOGIN owner/runtime role pairs, FORCE
RLS, transaction-local organization context, append-only enforcement, and only
own-schema `SELECT`/`INSERT` runtime grants. No shared table, cross-schema grant,
`BYPASSRLS`, DDL runtime privilege, destructive down migration, database,
extension, user, PVC, bucket, or endpoint is created. PostgreSQL execution for
this packet is `NOT_RUN_ENV_UNAVAILABLE`; static contract validation cannot be
reported as runtime database proof.

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

`KN-DOM-001` also owns one bounded correction to the separate
`ci/run_packet_argv.py` transport. The KN-001 bootstrap accidentally closed that
transport over KN-001's literal acceptance target list, which would reject every
later packet before the cumulative dispatcher could run. KN-DOM-001 replaces
only that literal equality test with closed generic `ARGV_ARRAY_V1` validation.
The hash-pinned packet, single deny-all-outbound process tree, exact offline
environment, local-only prefetch entry point, canary, digest rechecks, direct
argv, shell denial, and offline network/install-token denial remain mandatory.
This is not ownership of `Makefile`, `ci/run_make_target.py`, KN-001 handlers, or
future transport behavior beyond the declared closed validation contract.

The packet also corrects one KN-001 test-range defect in
`tests/common/test_security_sql_delivery.py`: the foundation ownership assertion
must compare the empty base to exact merged KN-001 commit `672e73e...`, not to
the current HEAD. Otherwise every valid later-packet file is falsely treated as
a KN-001 file. The amendment changes only the comparison endpoint and adds an
ancestor assertion; KN-001's original allowed set and all other foundation
security checks remain closed.

The same bootstrap packet is the only current owner of `PORTING.yaml` and
seeds a closed `NO_AUTHORIZATION` ledger. Reference/discovery-only packets cannot
edit it; a future copy transaction requires a revised `PORT_CANDIDATE` packet.

## Dependencies

- Upstream: contracts, SDK, trust policy/guardrail/evidence APIs, PostgreSQL/pgvector, OTel, tenant source endpoints, and model plane only for selected local embeddings/reranking.
- Downstream: runtime context assembly, execution workflows/tools, industry/conformance evidence.
- Trust/OPA loss fails closed for source access and memory writes/deletes. Model loss pauses indexing requiring embeddings but does not corrupt existing indexes.

`KN-001` pins the exact public contracts commit and release-manifest digests,
SDK-004 protocol commit/vector/module digests, TRUST-001 policy request/response
and client digests, and MET-003 policy/scanner/workflow digests in a local lock.
These are compatibility authorities, not mounted source dependencies. The
bootstrap uses only the standard library, local mocks, and dependency injection;
it never opens a predecessor or warm-start checkout during implementation or
acceptance.

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

The KN-DOM-001 acceptance also proves that the generalized packet transport
accepts both the unchanged KN-001 sequence and KN-DOM-001's declared sequence,
while denying empty phases, malformed argv, shell/environment launchers,
recursive verification, forbidden offline tokens, execution-contract drift,
packet mutation, missing isolation identity, and leaked authority paths.
The cumulative security target additionally proves the exact KN-001 commit is
an ancestor and its own base-to-foundation paths remain within the original
bootstrap boundary, independently of KN-DOM's packet-local path validation.

`common-contract` validates the immutable upstream lock, exact Python/lock
closure, canonical JSON/digests, closed records, privacy, idempotency, health
adapters, service ownership, and synthetic mocks. `security` validates the four
SQL ownership/RLS contracts, six Containerfile/chart sources, fail-closed
readiness, negative dispatch and `PORTING.yaml` vectors, path ownership, warm
source exclusion, and zero-bill policy. The two targets are cumulative direct
argv handlers owned only by `ci/targets/kn-001.json`; neither target downloads,
builds, deploys, opens a network route, or invokes a shell command string.

The source-only acceptance records PostgreSQL, image build, Kubernetes/OpenShift
render/deployment, runtime, live security, assurance, and tenant acceptance as
`NOT_RUN_ENV_UNAVAILABLE` or pending. It may prove only source and offline
contract/unit behavior; PR, merge, artifact/SBOM, release signature, deployment,
runtime, live security, assurance, and tenant acceptance remain independent
evidence axes.

Acceptance: white-goods mock sources ingest read-only, produce complete provenance/freshness/coverage, validate domain mappings, build a versioned index, return cited tenant-isolated context, and store/delete governed memory independently. Cross-schema/tenant access, SSRF, prompt injection metadata, stale-citation use, and secret leakage are denied. All services operate with egress restricted to declared tenant sources/local dependencies.

## Release and rollback

- Each harness/deployable is an independent module release with compatible contracts and migration range.
- Index builds are create-then-swap; failed builds retain previous ready index. Ontology/mapping versions are immutable.
- DB migrations use expand/contract. Rollback selects prior images and index/version pointers; source data, memory, tombstones, and provenance are retained. Destructive deletion requires an explicit signed request and receipt.
- For `KN-001`, rollback is source-only: revert the unconsumed bootstrap before a dependent packet merges. Never run a destructive database rollback or infer that source validation created an artifact, deployment, runtime state, assurance result, or tenant decision.

## Zero-bill rules

- No hosted embeddings/vector DB/object store, crawling SaaS, remote telemetry, automatic connector discovery, or runtime downloads.
- HTTP connectors are allowlisted tenant endpoints; cloud metadata/link-local/private-network SSRF rules are enforced unless an exact tenant destination is approved.
- Self-hosted offline CI only; no GitHub storage/cache/Packages, cloud databases, scheduled ingestion, or paid evaluation APIs.
- `KN-001` CI uses only pinned credential-free checkout on ephemeral self-hosted labels and invokes the external root-owned offline launcher. It has no hosted runner, service container, Actions cache/artifact/Packages, secret, network/package setup, or retained output.
