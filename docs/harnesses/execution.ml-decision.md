# Harness Specification: `execution.ml-decision`

## Contract

| Field | Value |
|---|---|
| Plane | Execution |
| Owning repository | `mas-harness-execution-plane` |
| API version | `harness.planeon.ai/v1alpha1` |

## Capabilities and non-goals

This harness serves approved deterministic ML and optimization artifacts for classification, regression, scoring, recommendation, constraint solving, and explainable decision support. It validates feature contracts and lineage, enforces thresholds/abstention, produces decision receipts, and separates advisory results from governed action.

It does not train arbitrary models in production, invoke tools directly, replace business approval, present LLM output as deterministic ML, or promote an artifact without unseen-set and lineage evidence.

## Owner and deployables

- `decision-service`: artifact registry projection, feature validation, inference/optimization, explanation, and receipts.
- Bounded batch scoring is an operation of `decision-service`; there is no separately selectable batch-worker image in the current catalog.
- Provider libraries are included only in the selected service image/profile.

## Dependencies, conflicts, and ordering

- Always required: `runtime.infrastructure`, `knowledge.data-integration`, `trust.security-safety`, `trust.governance-agentops`, `trust.observability-finops`.
- Required only when `model.inference` is selected for model-assisted decisions: `runtime.model-inference`.
- Production gate: current `trust.evaluation-assurance` evidence for the decision route, artifact, data lineage, and intended use.
- Optional: `knowledge.domain-semantic`, `execution.orchestration`, `execution.tool-skill-sandbox`.
- Conflicts:
  - Artifact without immutable training/evaluation data lineage and license.
  - Feature schema/domain digest mismatch.
  - Production route whose evaluation lacks a truly held-out/unseen set when the risk policy requires it.
  - Optimization problem without explicit objective, constraints, infeasibility behavior, and time bound.
  - Decision output wired directly to an action without orchestration/tool governance.

Artifact certification and feature readiness precede route activation.

## Provider implementations

- `planeon.sklearn`: scikit-learn pipelines serialized using an approved safe format/process; pickle ingestion is disabled by default.
- `planeon.onnx`: ONNX Runtime baseline for portable inference.
- `planeon.ortools`: OR-Tools constraint and optimization provider.

Additional providers require a module definition, license/custody review, sandboxed deserialization, and conformance suite.

## Configuration and runtime boundaries

```yaml
decisionRoutes:
  - id: string
    task: classification | regression | scoring | recommendation | optimization
    artifactRef: oci@sha256:...
    provider: planeon.sklearn | planeon.onnx | planeon.ortools
    featureSchemaDigest: sha256:...
    domainDigest: sha256:...
    evaluationDigest: sha256:...
    threshold: decimal-string-or-null
    abstainPolicy: below-threshold | out-of-domain | infeasible
    timeoutMilliseconds: integer
    explanation: native | feature-contribution | constraint-report
    modelAssistance: disabled | signed-local-route
```

- Secrets: none for local artifacts; source feature acquisition occurs through governed data/knowledge APIs.
- RBAC: no Kubernetes API access. Roles separate route activation, predict/solve, batch submission, and evidence view.
- Network: ingress from orchestration and approved clients; egress only to policy, data/knowledge APIs, evidence/usage, and OTel. No model/package registries at runtime.
- Storage: signed artifacts and cards in OCI; active route metadata and non-payload decision receipts in decision-owned execution tables. Feature payload retention is disabled unless an evidence plan permits classified storage.

## APIs, events, and state

```text
GET  /decision/v1/routes
POST /decision/v1/routes/{id}:predict
POST /decision/v1/routes/{id}:explain
POST /decision/v1/routes/{id}:optimize
POST /decision/v1/batches
GET  /decision/v1/operations/{id}
GET  /decision/v1/receipts/{id}
```

Artifact/route states: `REGISTERED → VALIDATING → CERTIFIED → ACTIVE`; alternatives `REJECTED`, `DEGRADED`, `SUPERSEDED`, `REVOKED`.

Decision outcomes: `DECIDED`, `ABSTAINED`, `INFEASIBLE`, `TIMED_OUT`, `INVALID_INPUT`, `FAILED`.

Emitted:

- `decision.route.activated.v1`
- `decision.completed.v1`
- `decision.abstained.v1`
- `decision.drift.detected.v1`
- `decision.route.revoked.v1`

Consumed: data-readiness changes, evaluation evidence, approval/promotion, and artifact revocation.

## Failures, retry, and rollback

- Artifact digest/signature, feature, domain, evaluation, or provider mismatch rejects activation.
- Invalid/out-of-domain inputs return `ABSTAINED` or `INVALID_INPUT`, never a coerced prediction.
- Loss or absence of inference disables the `model.inference`-conditioned decision path immediately; deterministic scikit-learn, ONNX, and OR-Tools routes remain ready and never acquire a hidden inference dependency.
- Pure deterministic inference is idempotent and may retry. Optimization retries only when its input digest and solver seed/config are identical.
- Timeout returns no partial action recommendation unless the contract defines a verified incumbent and labels it incomplete.
- Active route change is atomic; failure retains last-known-good artifact/evaluation digests.
- Drift or revoked evaluation can degrade/disable the route according to policy; downstream action remains gated independently.
- Rollback reactivates a previously certified compatible artifact.

## Evidence and readiness gates

- Artifact, code, dependency, feature, domain, training/validation/test data, and license lineage.
- Leakage/source-confounding checks and genuinely unseen-set evidence appropriate to the risk tier.
- Metrics, subgroup/fairness analysis, calibration, uncertainty/abstention, robustness, and reproducibility.
- Solver feasibility, objective/constraint correctness, determinism/seed, and timeout behavior.
- Explanation fidelity and decision-receipt completeness.
- Drift thresholds and monitoring evidence.
- Security review of artifact loading/deserialization.

Production readiness requires current certified evaluation and an approved intended-use/model card.

## Profile behavior

- `minimal-local`: ONNX or small scikit-learn artifact, synchronous decisions, no online training.
- `enterprise`: multiple routes, bounded batch operations, abstention/drift policies, dedicated CPU/GPU quotas.
- `airgap-enclave`: artifacts, runtimes, evaluation data summaries, and licenses included in bundle; no registry/download.

## Tests

- Unit: feature validation, thresholds, abstention, route resolution, receipts, constraint translation.
- Contract: prediction/explanation/optimization APIs, events, data/evidence integrations.
- Evaluation: reproducible metrics, unseen fixtures, subgroup/calibration, infeasible and out-of-domain inputs.
- Security: malicious artifact, pickle rejection, shape/resource bombs, tenant route crossover, payload leakage.
- Failure: timeout, solver infeasibility, corrupt artifact, evaluation revocation, last-known-good rollback.
- Air gap/platform: AMD64/ARM64 ONNX/scikit paths and selected accelerator closure.

## Sol-high implementation packets

1. `EXEC-001-foundation`: common execution kernel, tenant RLS/inbox/outbox, task/event contracts, images, and state-model tests.
2. `EXEC-ML-001`: signed artifact/provenance/evaluation admission, scikit-learn/ONNX/OR-Tools adapters, safe loading, feature contracts, abstention, bounded optimization, explanation, deterministic receipts, drift/revocation, and rollback.
3. `EXEC-002-resilience`: corrupt/malicious artifacts, provider/store outages, duplicate calls, timeouts/infeasibility, tenant isolation, and offline campaign.

Every packet keeps training out of the production service and actions behind orchestration/tool governance.
