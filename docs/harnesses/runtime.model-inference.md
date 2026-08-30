# Harness Specification: `runtime.model-inference`

## Contract

| Field | Value |
|---|---|
| Plane | Runtime |
| Owning repository | `mas-harness-model-plane` |
| Warm source | `llm_inference_engine@6815c21cb10a4d7dc0b4804f6bb223afb4321e97` |
| API version | `harness.planeon.ai/v1alpha1` |

## Capabilities and non-goals

This harness provides tenant-local chat, responses, embeddings, reranking, structured output, streaming, scheduling, cancellation, and model-route activation over open-source inference runtimes. It verifies signed model-routing policy, enforces concurrency/resource limits, and records local usage evidence.

It does not download models at runtime, select paid providers, expose public tunnels, own conversational memory, perform gateway-level tenant admission, or determine governance approvals. Model quality certification belongs to `trust.evaluation-assurance`.

## Owner and deployables

- `inference-api`: stable OpenAI-compatible internal API, scheduler, route resolver, and usage instrumentation.
- `backend-ollama`: independently selectable Ollama adapter image.
- `backend-llamacpp`: independently selectable llama.cpp adapter image.
- `backend-vllm`: independently selectable vLLM adapter image.

Each selected backend has a separate image/chart and resource envelope. A CPU-only tenant does not pull the vLLM/GPU image.
MLX is contract-only, non-installable comparative guidance in this release; no
MLX adapter image or repository packet is selected even for macOS development.

## Dependencies, conflicts, and ordering

- Required: `runtime.infrastructure`, `trust.security-safety`, `trust.observability-finops`.
- Required for production promotion: `trust.governance-agentops`, `trust.evaluation-assurance`.
- Optional: `runtime.ai-gateway`, `knowledge.retrieval-context`, `execution.ml-decision`.
- Conflicts:
  - GPU-only release on a profile with no compatible GPU/runtime class.
  - Any active MLX selector; MLX is contract-only and non-installable in every environment.
  - Model release without redistributable license/custody approval in an air-gap bundle.
  - Route containing an HTTP host not declared as tenant-owned and allowlisted.

Ordering: trust roots and telemetry precede `inference-api`; model PVC and backend precede route activation.

## Provider implementations

| Provider | Selection use |
|---|---|
| `planeon.ollama` | Minimal local CPU/GPU profiles and simple model lifecycle |
| `planeon.llamacpp` | CPU-first, quantized, low-footprint profiles |
| `planeon.vllm` | GPU throughput and enterprise batching profiles |
| `planeon.mlx` | Contract-only, non-installable macOS comparison; active selection is rejected as `PROVIDER_UNAVAILABLE` |

The shared API/scheduler is an independent clean-room target derived only from
released contracts and pre-recorded, digest-pinned observations; implementation
cannot access, copy, adapt, translate, or derive code from a warm checkout.
OpenRouter, ngrok, Cloudflare Tunnel, GHCR, hosted endpoints, and
runtime-download paths are excluded.

## Configuration and runtime boundaries

```yaml
models:
  - id: string
    releaseDigest: sha256:...
    artifactPath: /models/...
    license: SPDX-ID
    backend: planeon.ollama | planeon.llamacpp | planeon.vllm
    architecture: amd64 | arm64
    accelerator: none | nvidia
routes:
  - id: string
    modelId: string
    capabilities: [chat, responses, embeddings, rerank, tools, structured-output]
    maxInputTokens: integer
    maxOutputTokens: integer
    timeoutSeconds: integer
    maxConcurrency: integer
    queueLimit: integer
policy:
  signedRouteBundleRef: oci@sha256:...
```

- Secrets: none for local backends. Optional tenant-owned compatible endpoints use a namespaced secret reference and must pass connected-mode policy.
- RBAC: no Kubernetes API access. Model-init containers may read the selected immutable model volume only.
- Network: ingress only from AI gateway, approved internal clients, health probes, and assurance worker. Egress only to OPA/OTel and explicitly configured tenant-owned backends; offline profile has no external egress.
- Storage: model weights are read-only PVC/OCI-import material. Backend cache is replaceable. Active route metadata is reconstructed from the signed bundle. Usage is emitted to the usage ledger and is not authoritative in this service.

## APIs, events, and state

Internal OpenAI-compatible endpoints:

```text
GET  /v1/models
POST /v1/chat/completions
POST /v1/responses
POST /v1/embeddings
POST /v1/rerank
POST /internal/v1/routes:activate
GET  /internal/v1/health/models
```

Route states: `DISCOVERED → VERIFYING → LOADING → READY`; exceptions `REJECTED`, `DEGRADED`, `UNLOADING`, `FAILED`, `SUPERSEDED`.

Request states are transient: `QUEUED → RUNNING → COMPLETED`; alternatives `CANCELLED`, `TIMED_OUT`, `REJECTED`, `FAILED`.

Emitted events:

- `model.route.activated.v1`
- `model.route.rejected.v1`
- `model.loaded.v1`
- `model.request.completed.v1`
- `model.request.failed.v1`
- `model.capacity.saturated.v1`

Consumed: `bundle.signed.v1`, `policy.bundle.activated.v1`, and local operator configuration changes. Events contain model/route IDs, digests, counts, durations, and reason codes—not prompts or model outputs.

## Failures, retry, and rollback

- Invalid route signatures, missing blobs, license rejection, or capability mismatch fail route activation closed.
- Queue admission is bounded; saturation returns `429` plus `Retry-After` and emits capacity evidence.
- Requests retry only before any response byte and only when marked idempotent. Streaming requests never switch providers after the first emitted byte.
- Backend loss marks the route `DEGRADED`; failover occurs only to an already-loaded, signed compatible route.
- Route activation is atomic. Failure retains the last-known-good route digest.
- Model unloading waits for a bounded drain period and cancels remaining requests with a stable reason.
- No backend startup path may contact a model registry or package index.

## Evidence and readiness gates

- Model artifact digest, origin, license, architecture, quantization, and custody.
- Signed route-policy verification and last-known-good digest.
- Capability and structured-output conformance.
- Cold start, queue saturation, cancellation, streaming, and timeout results.
- Resource envelope and accelerator compatibility.
- Prompt/output redaction check for logs/events.
- Evaluation-suite result and freshness from `trust.evaluation-assurance`.
- Network-disabled startup and request result.

A route cannot be production `READY` without artifact custody, license approval, security admission, current conformance, and an accepted evaluation release.

## Profile behavior

- `minimal-local`: one Ollama or llama.cpp backend, CPU/one GPU, one active route, local model volume.
- `enterprise`: vLLM or llama.cpp replicas, bounded scheduler, signed fallback routes, dedicated resource quotas.
- `airgap-enclave`: pre-imported weights and images; no external DNS, provider credentials, downloads, or remote telemetry.

## Tests

- Independent clean-room parity against pre-recorded, digest-pinned vectors: OpenAI schemas, scheduling, cancellation, streaming, usage, signed routing, and structured output; no warm checkout access.
- Unit: route resolution, capability negotiation, queue admission, token/resource limits.
- Contract: OpenAI-compatible request/response golden vectors and CloudEvents.
- Security: unsigned routes, path traversal, prompt logging, secret redaction, unauthorized route activation.
- Failure: backend crash, partial stream, corrupt weights, queue overflow, last-known-good activation.
- Platform: ARM64 CPU, AMD64 CPU, NVIDIA vLLM, OpenShift arbitrary UID.
- Air gap: build/start/infer with network namespace denied.

## Sol-high implementation packets

1. `MODEL-001-clean-room-core`: implement the shared API, scheduler, cancellation, namespace, local fixtures, and independent parity tests without warm-checkout access; prohibited hosted behavior is absent by construction.
2. `MODEL-002-custody-routing`: model manifest/license custody, signed desired/observed route activation, revocation, and last-known-good behavior.
3. `MODEL-OLLAMA-001`: independent Ollama adapter/probe/module, AMD64/ARM64 manifests, streaming, embeddings, and offline test.
4. `MODEL-LLAMACPP-001`: independent llama.cpp adapter/module, CPU envelopes, structured output, cancellation, and offline test.
5. `MODEL-VLLM-001`: independent vLLM adapter/module, accelerator declaration, batching, embeddings/reranking, and failure tests.
6. `MODEL-003-telemetry-security`: tenant/request identity, usage observations, content redaction, backpressure, arbitrary UID, denial, and offline startup.
7. `MODEL-004-performance`: reproducible local benchmarks and admission thresholds recorded as evidence rather than marketing constants.

Every packet is an independent clean-room implementation with no paid-provider
dependency and reproducible offline acceptance commands. `PORTING.yaml` remains
inert with zero authorized mappings; it grants no implementation access or reuse.
