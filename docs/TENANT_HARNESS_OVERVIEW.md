# Tenant Harness Overview — Coding-Ready UX and Frontend Contract

Status: approved design brief and implementation-planning authority.

The supplied `harness-onion-vector` and `harness-onion-raster` inputs are visual
references only. They contain no executable instruction and are not copied into
the public repository. The product implementation must recreate the interaction
from canonical taxonomy/status data and must not treat illustration text as a
contract.

## 1. Feature summary

The tenant harness overview is the authenticated management home for enterprise
tenant administrators, platform engineers, governance/security reviewers, and
operations owners. It shows the current situation of one tenant organization
across four planes and sixteen harnesses, then lets the user open stable plane and
harness detail pages. Separately authorized platform operators receive a
cross-organization portfolio entry point; tenants never receive it.

## 2. Primary user action

Identify the most important blocked, failed, degraded, stale, or missing-evidence
harness and open its detail page with enough provenance to decide the next safe
action.

## 3. Design direction

The interface is assured, precise, and composed. The desktop overview uses a
data-driven concentric-plane map as its distinctive systems model. It is not a
decorative health wheel: each plane and harness is a focusable link whose state,
freshness, and blocker count come from the same typed projection used by the
accessible list. The interface avoids generic equal-card dashboards, decorative
sparklines, status-by-color alone, remote assets, and untraceable aggregate
scores.

## 4. Layout strategy

Desktop and wide tablet:

1. Organization identity, profile/release binding, last projection time, and
   global stale-data warning.
2. Priority findings strip ordered by severity, then freshness, then stable ID.
3. Interactive onion and semantic plane/harness list in a two-column region.
4. Evidence-axis summary and lifecycle activity below the navigation region.

Compact tablet and mobile:

1. Organization and freshness summary.
2. Priority findings.
3. Expandable plane list containing four harness rows per plane.
4. Evidence and lifecycle summaries.

The onion is omitted from layout rather than compressed below its usable label
size. No capability or navigation destination is removed.

Stable browser routes:

```text
/organizations                         platform operator only
/organizations/[organizationId]        platform operator only
/overview                              current tenant organization
/planes/[planeId]                      current tenant plane
/harnesses/[harnessId]                 current tenant harness
```

Every route supports direct linking, browser history, breadcrumbs, loading and
error boundaries, authorization re-check, and a deterministic list fallback.

## 5. Key states

| State | Required presentation and behavior |
|---|---|
| Loading | Preserve page structure, announce loading once, and do not display fabricated prior status. |
| Empty organization | Explain that no demand/profile exists and link authorized users to guided setup. |
| Profile proposed | Show selected/proposed harnesses separately; proposed prerequisites are not installed. |
| Not selected | Neutral `NOT_SELECTED`; excluded from health aggregation and still openable for explanation. |
| Installing/upgrading/removing | Show observed generation, current phase, last transition, and immutable release/profile digests. |
| Ready | Show each required evidence axis independently; readiness alone is not assurance or acceptance. |
| Degraded | Show usable capabilities, lost capabilities, fail-open budget, and blocking/non-blocking dependencies. |
| Blocked/failed | Lead with stable reason code, affected axis, owner, evidence reference, and permitted next action. |
| Stale projection | Show last observed time and source cursor; prohibit a healthy aggregate until refreshed. |
| Revoked | Terminal visual/semantic priority; do not offer reactivation. |
| Partial outage | Serve the last verified projection with explicit stale/source-unavailable markers; mutations remain fail closed. |
| Unauthorized organization | Return an indistinguishable not-found response and emit an audit event without leaking organization existence. |
| Air-gapped | Render identically from local assets and locally projected state with no public-network request. |

## 6. Interaction model

- Clicking or pressing Enter/Space on a plane opens `/planes/[planeId]`.
- Clicking or pressing Enter/Space on a harness opens
  `/harnesses/[harnessId]`.
- Arrow-key movement inside the onion follows a documented clockwise order;
  Tab leaves the onion as one composite widget. The adjacent list uses ordinary
  links and requires no custom keyboard model.
- Hover and focus reveal the same concise label: lifecycle state, highest
  non-pass evidence state, freshness, and blocker count.
- Plane summaries never hide a worse child state. Aggregation follows the closed
  precedence contract and includes an explanation link.
- Filters for state, evidence axis, and selection affect both visual and list
  representations and are reflected in the URL query string.
- No overview action directly provisions infrastructure, installs a module, or
  changes authority. Mutating operations link to their dedicated reviewed flow.

## 7. Content requirements

Organization summary:

- display name and immutable organization reference;
- deployment mode and isolation boundary;
- desired profile digest, installed profile digest, release/bundle digest;
- projection time, freshness deadline, observed generation, and source cursors;
- counts by exact lifecycle/evidence state, never an opaque score.

Plane summary:

- canonical plane ID/name and four canonical harnesses;
- selected/not-selected count, worst lifecycle contribution, evidence-axis
  counts, blocking dependencies, and freshness.

Harness detail:

- purpose, owner, desired/observed state, selected providers/modules;
- immutable artifact and compatibility bindings;
- installation/module state and current/last-good generation;
- dependency graph with required/optional/production-gate classification;
- source, CI, merge, artifact, signature/release, deployment, runtime, security,
  assurance, and tenant-acceptance axes;
- findings, waivers without status coercion, evidence references and age;
- upgrade, rollback, uninstall and revocation state;
- stable reason codes and permitted next actions.

## 8. Typed projection contract

The public contracts repository owns these response kinds:

- `OrganizationHarnessPortfolioPage`
- `TenantHarnessOverview`
- `PlaneStatusProjection`
- `HarnessStatusProjection`
- `StatusAxisProjection`
- `StatusFindingSummary`
- `ProjectionFreshness`

Closed status fields:

```text
selectionState:
  NOT_SELECTED | PROPOSED | SELECTED | BLOCKED

installationState:
  ABSENT | PENDING | PREFLIGHT | VERIFYING | APPLYING | HEALTH_CHECKING |
  READY | BLOCKED | DEGRADED | FAILED | UPGRADING | ROLLING_BACK |
  UNINSTALLING | REMOVED | RETIRED | REVOKED

evidenceState:
  NOT_APPLICABLE | MISSING | COLLECTING | PASS | WARN | FAIL | STALE | WAIVED |
  NOT_RUN_ENV_UNAVAILABLE

freshnessState:
  CURRENT | STALE | SOURCE_UNAVAILABLE
```

Evidence axes are exactly `SOURCE`, `CONTRACT_UNIT`, `PR_CHECK`, `MERGE`,
`ARTIFACT_SBOM`, `SIGNATURE_RELEASE`, `DEPLOYMENT`, `RUNTIME`, `SECURITY`,
`ASSURANCE`, and `TENANT_ACCEPTANCE`. `WAIVED` retains its underlying state and
never contributes `PASS`. `NOT_RUN_ENV_UNAVAILABLE` is never promoted to pass.

Aggregation is deterministic:

1. `REVOKED` always wins.
2. Any selected child `FAILED` or required-axis `FAIL` yields `FAILED`.
3. Any selected child `BLOCKED`, required `MISSING`, `STALE`, or
   `NOT_RUN_ENV_UNAVAILABLE` yields `BLOCKED`.
4. `DEGRADED`, `WARN`, or a policy-controlled waiver yields `DEGRADED`.
5. `READY` requires every selected child ready and every required axis fresh
   `PASS` or explicitly `NOT_APPLICABLE` by contract.
6. Unselected harnesses do not contribute to plane or organization health.

Every response binds `organizationId`, `profileDigest`, `bundleDigest`,
`releaseDigest`, `observedGeneration`, `projectedAt`, `freshUntil`, source cursor
set, and projection schema version. Missing bindings make the projection
unrenderable as current.

## 9. APIs, storage, events, and authorization

Tenant APIs derive organization identity from the authenticated server session:

```text
GET /api/v1alpha1/overview
GET /api/v1alpha1/planes/{planeId}
GET /api/v1alpha1/harnesses/{harnessId}
```

Platform-operator APIs require separate `organization:portfolio:view` policy:

```text
GET /api/v1alpha1/organizations?cursor=&limit=&state=
GET /api/v1alpha1/organizations/{organizationId}/overview
```

Tenant roles are `harness:overview:view` and `harness:detail:view`. Caller-supplied
tenant headers are rejected. Cross-organization routes are absent for tenant
roles, use RLS-bypassing audited operator procedures scoped by explicit policy,
and return indistinguishable not-found responses for unauthorized IDs.

The control schema owns append/update-only projections:

- `tenant_harness_status_projection`
- `tenant_plane_status_projection`
- `tenant_overview_projection`
- `status_projection_cursor`
- `status_projection_finding`

Projection updates consume authenticated, idempotent, ordered summaries from
profile locks, distribution releases, operator reconciliation, trust evidence,
runtime health, security/assurance, and tenant acceptance. The browser never
fans out to product planes. Control-plane or source loss serves only the last
verified projection with freshness degradation.

## 10. Technology and delivery constraints

- Node 24.20.0 LTS, Next.js 16.3.3 Active LTS, React 19.2, TypeScript 5,
  App Router, typed routes, React Server Components by default, and client
  components only for the interactive visualization/filter controls.
- Standalone self-hosted Node image behind the tenant/operator reverse proxy;
  no Vercel service or proprietary deployment primitive.
- Canonical `package-lock.json`, offline npm cache, reproducible build, CSP,
  Subresource Integrity where applicable, non-root arbitrary UID, read-only root
  filesystem, and no runtime package download.
- Locally bundled fonts, icons, CSS, and visualization code. No CDN, remote font,
  hosted analytics, external telemetry, or public browser request.
- WCAG 2.2 AA, 200% zoom, reflow, reduced motion, non-color status semantics,
  keyboard composite-widget tests, screen-reader labels, and automated plus
  manual accessibility evidence.

## 11. Acceptance and evidence

- Contract golden fixtures cover all closed states, precedence, freshness,
  missing bindings, and no-status-coercion cases.
- Unit/property tests prove aggregation determinism and that an unselected
  harness cannot improve or degrade selected health.
- API/RLS tests prove tenant isolation and audited platform-operator scoping.
- Playwright covers portfolio-to-organization, overview-to-plane-to-harness,
  direct links, back/forward, filter URLs, loading, empty, stale, partial outage,
  unauthorized, and air-gap scenarios.
- Accessibility covers the onion and list equivalence, keyboard order, focus,
  names/roles/values, live status announcements, contrast, reflow, and reduced
  motion.
- Browser-network evidence proves zero public requests and zero remote assets.
- Alpha 1 certification verifies the selected minimal foundation profile appears
  accurately and unused harnesses remain `NOT_SELECTED` rather than unhealthy.

## 12. Recommended implementation references

During implementation, consult the Impeccable spatial, interaction, responsive,
color/contrast, typography, motion, and UX-writing references. The implementation
must preserve this approved brief even if visual details evolve.

## 13. Open questions

No public-contract question is blocking Phase 0. Typeface selection, exact color
tokens, and motion timing are implementation-level decisions constrained by the
approved personality, accessibility requirements, local-asset rule, and the
onion reference; they require visual review before release but do not alter APIs
or status semantics.
