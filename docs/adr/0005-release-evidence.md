# ADR 0005: Release locks preserve independent evidence axes

- Status: Accepted
- Date: 2026-08-30
- Decision owner: Harness Engineering maintainers
- Packet: `MET-005`

## Context

The platform will eventually assemble artifacts from thirteen independently
released repositories. A Git commit, green CI run, merge, built artifact,
signature, successful deployment, healthy runtime, assurance result, and tenant
decision are different facts produced by different authorities. Treating any
one as proof of another would create false readiness and could allow a source
change to appear production-ready without an artifact, target, or tenant.

Phase 0 has no product repository releases. The release authority must therefore
be executable and testable without inventing artifacts or overstating current
operational evidence.

## Decision

`schemas/release-set.schema.json` is the closed Draft 2020-12 structural
authority. A release lock binds the tracked repository registry and evidence
policy by SHA-256, exact repository IDs and names, immutable Git commits and
release tags, artifact content, SBOM, license, and signature digests, and
evidence records bound to exact subject digests and validity windows.

Component evidence contains exactly `SOURCE`, `CI`, `MERGE`, `ARTIFACT`, and
`SIGNATURE`. Release/environment evidence contains exactly `DEPLOYMENT`,
`RUNTIME`, `SECURITY`, `ASSURANCE`, `TENANT_ACCEPTANCE_CANDIDATE`, and
`TENANT_ACCEPTANCE`. One evidence digest may satisfy only one axis. Only fresh
`PASS` satisfies a required gate; missing, collecting, warning, failure,
not-applicable, unavailable, stale, waived, pending, and rejected states remain
non-passing.

Promotion is recomputed from `release/evidence-policy.yaml`:

1. `ARTIFACT_RELEASE` requires all five component axes for every repository.
2. `PLATFORM_DEPLOYABLE` additionally requires deployment and runtime.
3. `PLATFORM_CERTIFIED` additionally requires security and assurance.
4. `TENANT_ACCEPTED` additionally requires a passing acceptance candidate and a
   separate tenant-acceptance record from an independent producer.

No earlier gate implies a later one. `NOT_RUN_ENV_UNAVAILABLE` is honest
evidence of non-execution and never a pass. A waiver never converts another
state to `PASS`.

`release/repos.lock.json` is intentionally an `INERT_LOCK` with zero repository
or artifact records and the blocker `NO_PRODUCT_RELEASES_PUBLISHED`. It is the
truthful current authority, not a release. `release/fixture-release-set.yaml` is
unmistakably `SYNTHETIC_FIXTURE` data covering all thirteen repositories. It
proves artifact-release validation while keeping deployment, runtime, security,
assurance, and tenant decisions unavailable or pending.

`scripts/build_release_lock.py` validates an input before exclusively creating
deterministic canonical JSON. It never overwrites a lock. The checker performs
schema validation, authority-digest verification, exact registry coverage,
mutable-reference denial, subject/evidence binding, freshness checks, evidence
separation, and independent promotion recomputation entirely offline.

## Consequences

- A future platform release can be reproduced from immutable repository and
  artifact identities without relying on branches, tags such as `latest`, or a
  network registry during verification.
- Source, CI, merge, artifact, and signature success can publish artifacts but
  cannot claim a deployment or live environment.
- Technical certification cannot create tenant acceptance. The tenant decision
  remains separately scoped to a tenant, environment, and release bundle.
- The same lock bytes and policy digest can be transported into an air-gapped
  environment and evaluated without a reduced trust model.
- Phase 0 ends with planning and executable governance authorities only; it does
  not publish, sign, deploy, certify, or accept a product release.

## Verification

- The canonical inert lock validates and contains no fabricated release.
- The synthetic fixture covers exactly thirteen repositories, immutable commits,
  thirteen artifact records, and every evidence axis.
- Two generated JSON locks from the same source are byte-identical.
- Negative vectors reject mutable references, missing repositories or axes,
  unknown members, duplicate keys, authority or subject mismatches, cross-axis
  evidence reuse, future/expired evidence, false promotion, and conflated tenant
  acceptance.
- All acceptance executes through the hash-pinned MET-005 offline wrapper with
  outbound network denied.

## Rollback

Revert the schema, policy, inert lock, synthetic fixture, builder, checker,
tests, and this decision together. Because no product consumes the Phase 0 lock
and no release is published, rollback does not mutate a product repository or
withdraw any operational release.

## Rejected alternatives

- Populate the canonical lock with planned or synthetic product releases:
  rejected because fixtures are not operational evidence.
- Infer deployment from a signed artifact or runtime from deployment: rejected
  because each axis has a different subject and producer.
- Treat an acceptance candidate as tenant acceptance: rejected because only a
  separate tenant authority can make that decision.
- Resolve mutable tags or online registries during validation: rejected because
  the result would be network-dependent and incompatible with air-gapped use.
- Overwrite an existing lock in place: rejected because review and rollback need
  immutable history.
