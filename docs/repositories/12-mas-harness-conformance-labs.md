# Repository Plan: `mas-harness-conformance-labs`

Current Alpha-2 dispatch: [MET-REPAIR-010 protected policy-observation prerequisite](../alpha-2/POLICY_OBSERVATION_READINESS.md).
Catalog 136; accepted backend source through CONF-LIVE-002 (127 files / 279 tests).
CONF-LIVE-003 waits for this authority's source/CI/merge/local exact-main closure.
Older publication sections below retain their historical states, not current instructions.

## Purpose and boundaries

This repository supplies two layers: a reusable contract/conformance kit runnable by every product repository, and deployment certification campaigns for complete profile bundles. It proves behavioral parity, interoperability, tenant isolation, Kubernetes/OpenShift/K3s compatibility, upgrade/rollback, physical air-gap operation, and white-goods acceptance.

Non-goals:

- No product service, canonical contract, cluster/cloud provisioning, hosted test infrastructure, paid evaluation, or automatic claim that an unavailable environment passed.
- Static rendering, unit tests, green CI, merge, artifact build, deployment, runtime behavior, security assurance, and tenant acceptance remain distinct evidence axes.
- The lab never modifies the five warm repositories.

## Repository structure and exact tree

This tree projects the current task-packet `allowedPaths`. Directory entries do not authorize edits beyond the packet executed in a coding run.

```text
mas-harness-conformance-labs/
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
├── toolchain.lock
├── pyproject.toml
├── uv.lock
├── ci/
├── src/harness_conformance/
├── schemas/
├── campaigns/
│   ├── meta/
│   ├── parity/
│   ├── alpha1/
│   ├── alpha2/
│   ├── alpha3/
│   ├── platform/{kubernetes,openshift,k3s,airgap}/
│   ├── security/
│   ├── upgrade/
│   └── white-goods-enterprise/
├── parity/
│   ├── adapters/
│   ├── registry.yaml
│   └── vectors/
├── fixtures/
│   ├── environments/
│   ├── alpha1/
│   ├── alpha2/
│   ├── alpha3/
│   ├── platform/{kubernetes,openshift,k3s,airgap}/
│   ├── security/
│   ├── upgrade/
│   └── white-goods-enterprise/
├── docs/
│   ├── parity.md
│   ├── acceptance/white-goods-acceptance-template.md
│   └── reports/{airgap-template.md,alpha1-template.md,alpha2-template.md,alpha3-template.md,k3s-template.md,kubernetes-template.md,openshift-template.md,security-template.md,upgrade-template.md,white-goods-enterprise-template.md}
└── tests/
    ├── meta/
    ├── parity/
    ├── alpha1/
    ├── alpha2/
    ├── alpha3/
    ├── platform/{kubernetes,openshift,k3s,airgap}/
    ├── security/
    ├── upgrade/
    └── white-goods-enterprise/
```

## Package, toolchain, and interfaces

- Distribution/import/CLI: `planeon-harness-conformance` / `harness_conformance` / `harness-conformance`.
- Python 3.12.14, `uv` 0.12.7, pytest, Hypothesis, HTTPX, psycopg, cryptography, jsonschema, Kubernetes client, and OpenTelemetry reader; exact versions locked.
- Node 24.20.0 LTS and Playwright for portal/streaming interaction only; browsers are prefetched and locked.
- Cluster tools are pinned through the packet-owned `uv.lock` and local `ci/` prefetch manifest; environments are supplied locally by the operator. The suite never creates cloud infrastructure.
- Inputs: signed campaign, environment intake, bundle/profile digest, expected controls. Outputs: canonical `campaign-report.json`, JUnit, observations, evidence records, environment facts, and digest/signature manifest stored locally.
- Owned APIs, events, and stores: no hosted API, production event stream, or database. A local CLI may submit signed evidence records to a configured trust endpoint; otherwise it writes an OCI/file evidence artifact.
- The only live entry point is the external, root-owned
  `/opt/planeon/bin/harness-live-campaign-launch` on a preinstalled target-local
  ephemeral runner. Its only packet-declared input is
  `HARNESS_LIVE_EXECUTION_ENVELOPE`; the envelope contains every other absolute
  local reference, including the packet, kit, campaign/release, bundle, capacity
  authorization, TLS CA, and credential references. The launcher opens them
  no-follow/read-once and checks their signed digests before checked-out code.
  `PLATFORM_RELEASE` and `TENANT_LIVE_EXECUTION` independently sign the same RFC
  8785 payload. Release and tenant keys come only from
  `/etc/planeon/trust/release-trust-bundle.json` and
  `/etc/planeon/trust/tenant-trust-bundle.json`; the separate capacity record has
  its own `CAPACITY_OPERATOR` signature. `ci/verify-live-campaign.sh` is only an
  inner runner and rejects direct or GitHub-CI execution.
- Endpoint authority is embedded in the dual-signed envelope and admits only
  `KUBERNETES_API_PROXY`, `CAMPAIGN_PROXY`, `LOCAL_REGISTRY`, and
  `LOCAL_EVIDENCE_SINK`. Proxy kinds use `PREAUTHORIZED_PROXY`; local kinds use
  `LOCAL_PREEXISTING`. Every tuple binds its endpoint ID, IP/port/TLS identity,
  credential reference, authorization-policy digest, approved non-metered cost
  disposition, and `discovery: false`. Services created by a campaign are probed
  only through the signed proxies; campaign code never receives a
  discovered Pod/Service address, wildcard, CIDR, DNS suffix, cloud endpoint,
  metadata endpoint, provider key, or container/CRI socket.
- A capacity operator independently signs the bounded namespace, service
  account, quota, preallocated resources, proxy scope, and server-side zero-cost
  mutation-policy digest. The campaign identity cannot bypass that admission
  policy. It rejects load balancers, dynamic storage, autoscaling/cloud-provider
  resources, external artifacts/egress, and unknown cost dispositions.

The closed machine shape is
[`live-campaign-execution-envelope.schema.json`](../../schemas/live-campaign-execution-envelope.schema.json).
The exact schema-aligned envelope fields, common RFC 8785 signature coverage, trust and
revocation rules, endpoint/proxy contract, capacity authorization, zero-cost
admission rules, canonical statuses, per-campaign evidence-axis table, and
required negative tests are normative in
[`TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md`](../TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md).
The current planning record alone is not live authority: live execution remains
blocked until `CONF-001` implements those schemas/tests and the externally
custodied trusted launcher is installed.

Result per test/control is exactly `PASS`, `FAIL`, `WARN`, `NOT_APPLICABLE`, or `NOT_RUN_ENV_UNAVAILABLE`. Missing environment never becomes pass. Reports record source SHA, artifact digest, cluster facts, command/tool versions, timestamps, sanitized output hashes, and evidence axis.

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

- Upstream: contracts, SDK, industry fixtures, distribution bundle, operator/plane releases, public trust keys, and explicit local environment intake.
- Downstream: trust evidence service and meta release lock consume signed reports.
- The reusable kit is versioned with contracts; product repositories vendor/pin the kit artifact, not Git `main`.

## Warm-source mapping

Public source provenance is recorded only in `architecture/reuse-map.yaml`, `architecture/reuse-path-index.yaml`, and packet `sourceReuse` entries. Non-public planning inputs have already been distilled into independent public contracts and acceptance criteria; their repository names, commits, paths, and object IDs are deliberately omitted. They are not mounted or required during implementation. No source is copy-authorized.

## PR packets

1. `CONF-001-kit`: CLI, campaign/evidence schemas, environment intake,
   contract/lifecycle/event kit, result semantics, signing, reproducible trusted
   live-launcher artifact, generic Make dispatch, and meta-tests. The artifact
   gains authority only after independent reviewed root-owned installation.
2. `CONF-002-parity`: warm-source vector registry, source hashes, parity runners, behavior-change records, and destination adapters.
3. `CONF-A1-001`: questionnaire-to-installed white-goods business/domain/data foundation campaign.
4. `CONF-FIX-001`: offline OS/backend and strict canary correction, fixed transport bridge, complete predecessor discovery and fail-closed retirement of the unauthenticated live adapter; no live authority.
5. `CONF-LINUX-001`: early native Linux baseline campaign, closed build/probe evidence verifier and independent operator execution; no source/fixture substitution or Alpha-4 certification claim.
6. `CONF-FIX-002`: strict quoted-scalar packet parsing, one exact hash assertion and independent regression vectors; no packet reserialization or isolation change.
7. `CONF-FIX-003`: exact scalar-suite inventory amendment, test-only cumulative helper and twenty new methods; preserve 150 predecessor IDs and all production bytes.
8. `CONF-LIVE-001`: Session contracts and cumulative inventory; exact paths and cumulative commands in the approved backend guide.
9. `CONF-LIVE-002`: Protected Linux supervisor and isolation candidate; exact paths and cumulative commands in the approved backend guide.
10. `CONF-LIVE-003`: Fixed proxy transport and zero-cost admission; exact paths and cumulative commands in the approved backend guide.
11. `CONF-LIVE-004`: Native Linux build and ten fixed probes; exact paths and cumulative commands in the approved backend guide.
12. `CONF-LIVE-005`: Reproducible packaging and operator handoff; exact paths and cumulative commands in the approved backend guide.
13. `CONF-LIVE-006`: Trusted campaign integration and manual qualification declaration; exact paths and cumulative commands in the approved backend guide.
14. `CONF-A2-001`: cited read-only white-goods agent with local model/retrieval and failure injection. Also consumes CTRL-INTEGRATE-001 and separately requires fresh installed Alpha-1 foundation plus authenticated production overview, durable restart/replay and tenant/RLS evidence; fixtures or source-only completion cannot satisfy these live gates.
15. `CONF-A3-001`: approval/resume/tool receipt/compensation, sandbox, memory lifecycle, and tenant-isolation campaign.
16. `CONF-K8S-001`: live Kubernetes 1.35-1.37 matrix; each minor/platform/architecture result separate.
17. `CONF-OCP-001`: OpenShift 4.20 arbitrary UID/SCC/Route/NetworkPolicy/operator campaign.
18. `CONF-K3S-001`: single-VM K3s minimal AMD64/ARM64 campaign.
19. `CONF-AIR-001`: two-zone physical no-network export/import/install/runtime/upgrade evidence.
20. `CONF-SEC-001`: cross-tenant/API/DB/index/cache/network denial, forged artifacts/evidence, sandbox escape, prompt/tool attacks, secrets, and revocation.
21. `CONF-UPG-001`: operator/service/DB upgrade, crashes at every wave, last-known-good rollback, retention, and uninstall.
22. `CONF-WG-001`: complete enterprise journey and an unsigned tenant-acceptance
    candidate; a separate tenant signer owns the acceptance decision.

## Testing, verification, and acceptance

The `CONF-001` bootstrap packet declares
`prefetchCommands: [["make","prefetch"]]` and ordered
`offlineAcceptanceCommands:
[["make","meta-conformance"],["make","build-reproducible"],["make","zero-bill"],["make","acceptance-package-contract"]]`.
It also owns the generic `Makefile` dispatch for `campaign`, `evidence-verify`,
and `acceptance-package`; meta-tests must exercise all three. The last target
creates only an unsigned `TENANT_ACCEPTANCE_CANDIDATE`.
Later packets add unit, contract, meta-test, parity, composed-campaign,
security, and reproducibility checks as direct argv arrays. The executor
supplies the hash-pinned packet through `HARNESS_TASK_PACKET` and invokes only
`offlineExecution.wrapperArgv: ["./ci/verify-offline.sh"]` for the complete
ordered list.

The twelve environment-facing campaign packets repeat those argv arrays under a
closed `liveCampaignExecution` record. Offline PR acceptance runs with no live
authority and verifies honest `NOT_RUN_ENV_UNAVAILABLE` behavior. A manual
post-merge run uses the external trusted launcher with a dual-signed execution
envelope whose embedded exact endpoints share the same two signatures, plus a
separate digest-bound capacity authorization signed by `CAPACITY_OPERATOR`. Its
allowed axes are the exact per-packet ordered subset of `DEPLOYMENT`, `RUNTIME`,
`SECURITY`, `ASSURANCE`, and `TENANT_ACCEPTANCE_CANDIDATE` listed in the trusted
live-runner contract; `TENANT_ACCEPTANCE` is forbidden.
It never proves source, unit, PR-check, merge, artifact, signature/release, or
tenant acceptance. The white-goods campaign can assemble only an unsigned
candidate for a separate tenant decision.

Acceptance requires meta-tests that deliberately fail each evidence/status rule, signed reports, deterministic local campaigns, and explicit environment-unavailable results. Enterprise release requires passed foundation, read-only, governed action, security, upgrade/rollback, supported platform, architecture, physical air-gap, and white-goods acceptance campaigns; a green CI or rendered manifest alone cannot satisfy them.

## Release and rollback

- Conformance kit and campaign definitions have independent SemVer and contracts compatibility. Reports pin exact kit/campaign/environment/product digests.
- Evidence is immutable. Reruns create new reports and may supersede status without rewriting history.
- If a campaign regression is discovered, revoke that campaign release, rerun affected product releases with a corrected campaign, and update the meta release lock only after new evidence passes.

## Zero-bill rules

- Environments are local/pre-existing and explicitly supplied; no cloud API, cluster creation, DNS, hosted browser, paid judge, remote load generator, or third-party API key.
- Self-hosted ephemeral CI only; no Actions artifact/cache/Packages, scheduled monitoring, remote coverage/security upload, public tunnels, or external telemetry.
- Live campaigns are never scheduled from GitHub CI. They cannot discover or
  provision an endpoint and may reach only exact dual-signed embedded endpoints
  through the externally established target-local host OS allowlist. An independent
  capacity signature and server-side zero-cost mutation policy bound every
  Kubernetes write. Unavailable capacity is `NOT_RUN_ENV_UNAVAILABLE`, not an
  online fallback; invalid authority or an attempted boundary bypass is `FAIL`.
- Large logs/reports remain on the runner or signed local OCI evidence layout and are removed per retention policy after ingestion.

## Early Linux implementation gate

CONF-LINUX-001 owns the early campaign, evidence schema, fixed verifier and
additive common campaign/CLI/schema/live-context paths declared in its packet.
It follows CONF-A1-001 so common tests are ordered. Preserve all older handlers
and run the complete conformance suite, not only new Linux fixtures. Missing
signed Linux context is unavailable; generic capability flags and emulation
cannot close native qualification. The source kit may merge independently,
but runtime coding gates remain closed until fresh verified Linux PASS.

Detailed steps, cases, evidence bindings and rollback:
[Linux readiness](../alpha-2/LINUX_READINESS.md). Full Alpha-4 enterprise
certification and tenant acceptance remain independent.

## R1-R4 implementation boundary

[The approved amendment](../alpha-2/LINUX_READINESS_REPAIRS.md) must merge first.
CONF-FIX-001 then runs each predecessor suite explicitly, repairs both backend
checks and the creation-denial canary, adds the exact pinned transport bridge,
and removes unauthenticated live-adapter execution. Missing external endpoint
isolation remains unavailable. It never changes Makefile/dispatch or root code.

CONF-LINUX-001 may additionally append only LINUX_READINESS to models.HANDLERS
and the published control-result handler enum; all old definitions, enums,
outputs and fixtures stay intact. Its seven declared commands cover meta,
parity, alpha1, runner-boundary and linux-baseline suites, campaign and evidence
verification. Empty or omitted suites fail. No broad package initializer change
or legacy Alpha-1 import rewrite is needed. Native AMD64 PASS and separately
qualified ARM64 remain independent post-merge gates, never source-test claims.

## MET-REPAIR-004 test-ownership boundary

CONF-FIX-001 is merged at 07453d3e6313c836426545c454380176bc2a2ee1; all 83
source tests passed locally, in required PR CI and in local exact-main replay.
CONF-LINUX-001 additionally depends on MET-REPAIR-004 and may replace only
self.assertEqual(len(HANDLERS), 5) in the named canonical-schema test with the
exact ordered six-handler tuple. Every other byte/assertion stays unchanged.
New negative tests live in its Linux-owned directory and reuse the unchanged
inventory helper to cover all five suites and all 83 predecessor test IDs.
No runner-boundary path, new live authority, native PASS or tenant acceptance
is granted by this amendment. See [the exact scope](../alpha-2/LINUX_TEST_OWNERSHIP_REPAIR.md).

## Approved trusted live backend enablement — MET-LIVE-001

The [coding guide](../alpha-2/LIVE_BACKEND_READINESS.md) and closed
`architecture/live-backend-roadmap.json` add six sequential conformance packets
(CONF-LIVE-001 through CONF-LIVE-006), not new repositories or harnesses.
This publication recorded 130 packets; the current catalog contains 136. The 123 consumed packet YAML and all existing
architecture/legal/policy/release records remain byte-identical.

Only the six source-enablement packets may proceed before native qualification.
After their source closure, external operator installation and a fresh
independently signed native AMD64 qualification are required before
CTRL-INTEGRATE-001, MODEL-001, EXEC-001 or RUN-001. ARM64 qualification is separate.
CONF-LIVE-006 adds the twelfth possible manual campaign declaration with the
complete eight-command inventory; it grants no installation, target access,
provisioning or paid capability. The old seven-command CONF-LINUX-001 verifier
and all predecessor tests remain unchanged; the new packet has its own exact
pure authority/evidence adapter. Source fixtures never become native evidence.

Current phase/status and completed source checkpoints are in DEVELOPMENT_STATUS.md.
One packet, branch, PR and exact local/CI/main gate per run remains mandatory.

## Historical packet scalar compatibility publication — MET-REPAIR-007

The [exact correction guide](../alpha-2/PACKET_SCALAR_REPAIR.md) adds MET-REPAIR-007 and
CONF-FIX-002: **132 packets**, thirteen repositories, sixteen harnesses and
**twelve** unchanged possible live declarations. The preceding 130 packet YAML
and all existing architecture/legal/policy/release bytes remain immutable.
This is the retained 132-packet publication. The successor-inventory supplement below supersedes its dispatch status.

CONF-LIVE-001 is blocked after its quoted scalar identity failed before any
acceptance command or test ran. Complete CONF-FIX-002 in a separate product PR
first: change only the exact parser branch and one full-file hash assertion,
then add independent regression evidence in its three new owned files.
No packet reserialization, dependency, root policy, installation or isolation
change is authorized. Resume CONF-LIVE-001 only after corrective source,
local offline, required PR CI, merge and separate local exact-main closure.
Retain its original 103-file/120-test baseline and add corrective provenance
only within its existing paths; the six-root/eight-command inventory is fixed.
Native Linux, live backend, runtime and tenant acceptance remain separate gates.

## Approved cumulative inventory repair — MET-REPAIR-008

The [cumulative inventory guide](../alpha-2/SUCCESSOR_INVENTORY_REPAIR.md) adds
MET-REPAIR-008 and CONF-FIX-003: **134 packets**, thirteen repositories, sixteen
harnesses and twelve unchanged possible live declarations. All 132 previous
packet YAML and existing architecture/legal/policy/release bytes are immutable
(170 files). Neither old correction record is rewritten.

MET-REPAIR-007 and CONF-FIX-002 are complete as separate source/CI/merge/local
exact-main checkpoints. Source inspection subsequently found the scalar suite's
frozen 106-file inventory rejects the next ten legitimate files; the earlier
successor-readiness inference is withdrawn, not its actual 150-test PASS.
Complete the new authority and then CONF-FIX-003 in its separate product PR:
one exact three-hunk test change and four new files, all 150 previous test IDs
plus twenty new tests. The parser and every other predecessor stay fixed.

Require complete ordered stage path sets (110, 120, 127, 135, 141, 146, 151 files),
predecessor hashes/modes, real collection and strict malformed/link/partial-stage
negatives. CONF-LIVE-006 alone may later replace the single terminal unavailable
statement after unchanged launcher manifest/preflight checks, with a bounded
SOURCE_DELTA_ONLY proof in its already-owned qualification document. That proof
is source accounting, not execution authority or a code-safety certification.

CONF-LIVE-001 remains blocked until corrective source, local offline, required
localhost PR CI, merge and local exact-main close. Then reconcile cumulative
history within its existing ten paths and unchanged six-root/eight-command
acceptance. No signed consumer packet, root policy, dependency, installation or
billing boundary changes. Native Linux and tenant acceptance remain separate;
no phase-end model-effort transition is due.

## Approved proxy contract prerequisite — MET-REPAIR-009

The [strict proxy profile](../alpha-2/PROXY_CONTRACT_READINESS.md) closes credential and resource-rule
semantics for the new proxy without changing any accepted public wire schema,
134 existing packet YAML, product path grant, command inventory or signature role.
This one additive meta packet produces a 135-packet catalog and preserves all
176 predecessor authority files. It records SOURCE_INSPECTION_ONLY findings,
not a reproduced exploit or new product test failure.

Complete this authority before CONF-LIVE-003. Product implementation remains
in that packet's eight existing paths; preserve all 127 predecessor files and
279 test IDs. CONF-LIVE-004 owns actual probes, CONF-LIVE-005 the fixed client/server
candidate packaging, and CONF-LIVE-006 the already-bounded final hook. Mutual TLS,
independent server custody, actual policy/RBAC, durable reservations and exact-UID
cleanup must be tested independently; meta vectors are UNIT_VERIFICATION_ONLY.
Native qualification, runtime and tenant acceptance remain separate and unavailable.
No installation, key issuance, root-policy change, hosted runner or paid API is
part of this publication. Alpha 2 remains ongoing; no phase-end effort change is due.

## Approved protected policy observation — MET-REPAIR-010

Source-only prerequisite before CONF-LIVE-003: fixed local server-only observation,
independent operator custody and current enforcement evidence. Campaign API rules,
credentials, mutations and egress remain unchanged. The observer is a separately
installed open-source operator prerequisite, not an available or deployed product.
Current catalog 136; 135 predecessor YAML and strict proxy profile preserved.
Product stages 110/120/127/135/141/146/151 and eight paths/eight commands unchanged.
See the current dispatch link above for the closed schemas, native obligations,
recorded predecessor timing risk and separate acceptance gates. Alpha 2 ONGOING.
