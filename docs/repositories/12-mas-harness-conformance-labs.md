# Repository Plan: `mas-harness-conformance-labs`

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
4. `CONF-A2-001`: cited read-only white-goods agent with local model/retrieval and failure injection.
5. `CONF-A3-001`: approval/resume/tool receipt/compensation, sandbox, memory lifecycle, and tenant-isolation campaign.
6. `CONF-K8S-001`: live Kubernetes 1.35-1.37 matrix; each minor/platform/architecture result separate.
7. `CONF-OCP-001`: OpenShift 4.20 arbitrary UID/SCC/Route/NetworkPolicy/operator campaign.
8. `CONF-K3S-001`: single-VM K3s minimal AMD64/ARM64 campaign.
9. `CONF-AIR-001`: two-zone physical no-network export/import/install/runtime/upgrade evidence.
10. `CONF-SEC-001`: cross-tenant/API/DB/index/cache/network denial, forged artifacts/evidence, sandbox escape, prompt/tool attacks, secrets, and revocation.
11. `CONF-UPG-001`: operator/service/DB upgrade, crashes at every wave, last-known-good rollback, retention, and uninstall.
12. `CONF-WG-001`: complete enterprise journey and an unsigned tenant-acceptance
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

The ten environment-facing campaign packets repeat those argv arrays under a
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
