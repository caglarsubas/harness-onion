# Lab run-plan contract v1: GCP qualification run plans, leases and teardown reports (MET-LINUX-007)

Status: **CONTRACT_CANDIDATE_AWAITING_INDEPENDENT_REVIEW**. Roadmap item LAB-RUNPLAN-001, harness-onion slot 251 (packet
MET-LINUX-007). Review rounds and adoption are recorded in `status.json`. DATA_CHECK_ONLY: published data and an offline
checker. Nothing here touches a cloud, holds a credential or applies anything.

The owner's GCP compute is the Linux capacity for CONF-LINUX-001 and W06, and each run plan goes to the owner before it
starts (owner decision, 2026-10-15). This contract fixes what every run plan states and how its lease and teardown are
checked, so each approval is quick and the same (owner VR-D1, 2026-10-17). R00 publishes it and R12 consumes it. An edge
record registers R12's consumption when an R12 packet vendors the contract (Q-RP-9).

## Decisions

The owner's decisions, 2026-10-19, relayed by the lane monitor; `status.json` holds the message verbatim.

- **Q-RP-0 (a), clean room.** The contract is designed from the roadmap text (VR-D1) and the 2026-10-15 decision only.
  The owner's warm-start lab repository is not read: AGENTS rules 4 and 10, and its licence evidence (WARM-PROVENANCE-001)
  is still open. Its practices appear here as requirements, not as copied material.
- **Q-RP-1 (a), scope.** Three documents and one checker.
- **Q-RP-2 (a), cost.** A dated rate card and line items; the checker recomputes the total against the owner's ceiling.
  Budgets are alert-only.
- **Q-RP-3 (a), project separation.** No project id of the owner's organisation is published. A plan declares that its
  run project is separate from the lab foundation, and the owner confirms it at approval. Every id in the vectors is
  invented.
- **Q-RP-4 (a), observer.** A dedicated read-only observer per run, with closed viewer roles, no exported keys, and
  payload-free observations.
- **Q-RP-5 (a), exposure.** No external address or ingress by default. Each exception is listed, and the residual check
  confirms it is gone.
- **Q-RP-6 (a), approval binding.** The owner approves the plan's canonical sha256, and the lease binds it.
- **Q-RP-7 (a), packet id.** MET-LINUX-007.
- **Q-RP-8 (a), runbook location.** This README only.
- **Q-RP-9 (a), R12 edge.** Later.

## Files

| File | Content |
|---|---|
| `run-plan.schema.json` | `planeon.internal.lab-run-plan/v1`: one run on the owner's GCP compute |
| `lease.schema.json` | `planeon.internal.lab-run-lease/v1`: the owner's approval of one plan sha256, with its window |
| `teardown-report.schema.json` | `planeon.internal.lab-run-teardown/v1`: what the run's observer saw after teardown |
| `vectors.json` | Three positive runs (plan, lease and teardown each accepted), 99 negatives (68 plan, 11 lease, 20 teardown) and 9 parse negatives, each with its recorded refusal |
| `status.json` | Contract state, decisions, review rounds |
| `REVIEW_BRIEF.md` | The independent contract review's brief |
| `../../scripts/lab_run_plan.py` | The offline checker |

The checker is standard library only. Run it from the repository root:

| Command | What it does |
|---|---|
| `python3 -I -B scripts/lab_run_plan.py` | checks the schemas and replays every vector |
| `... plan PLAN` | checks a plan and prints the sha256 the owner approves |
| `... lease PLAN LEASE` | checks a lease against its plan |
| `... teardown PLAN LEASE REPORT` | checks a teardown report, checking the lease again first |

A refused document prints `refused: <rule>` and exits 1. A file that is not UTF-8, or starts with a byte-order mark, is
refused by its rule. A file that cannot be read, or is not well-formed JSON, is refused the same way and the line names
the error's class instead of a rule (for example `refused: JSONDecodeError`).
A usage error prints the usage and exits 2. Only an accepted plan prints its sha256.

**The schema subset.** The three schemas use one closed JSON Schema subset, with this checker's own semantics. They
declare no external dialect.
- `check_schema` refuses any other keyword.
- It refuses any schema with `properties`, `required`, `additionalProperties` or an object type that is not exactly a
  closed object, with every key required and no other key allowed.
- It refuses `items` outside an array schema, and any schema without a `type`, a `const` or an `enum`.
- Each value keyword must apply to the schema's type and have a value of its own type: `pattern` and the lengths only
  on strings, the bounds only on numbers and integers, the item counts and `uniqueItems` only on arrays; `enum` is a
  non-empty list and `type` names known types.

So the published schemas and the checker cannot drift apart silently. A value may be `null` only where the schema says
so.

**Numbers and strings.** JSON is parsed strictly: UTF-8 without a byte-order mark, no duplicate keys, no non-finite
numbers, no integers beyond 10^12, and no string that is not valid Unicode (a lone surrogate escape). An integral number is written without a decimal point
or exponent, so `6` is accepted and `6.0` is refused. Each document therefore has exactly one canonical form. The parse
negatives in `vectors.json` replay each of these refusals.

## The three documents

### Run plan

| Section | It states | The checker adds |
|---|---|---|
| `purpose` | the gate (CONF-LINUX-001, W06 or PACKET) and a summary | a packet id exactly for a PACKET run |
| `workload` | the repository, its commit and the sha256 of the argv set the run executes | |
| `project` | the run project's id and `separateFromLabFoundation: true` | the owner confirms separation at approval (Q-RP-3) |
| `location` | region and zone | the zone lies in the region |
| `machines` | up to four groups: machine type, count, boot disk size and its rate card SKU, and an image pinned by its exact name | |
| `maxDurationHours` | at most 72 | the lease may not last longer |
| `cost` | a dated rate card (date, source label, unit prices), line items, the total, the owner's ceiling | see the cost rules below |
| `budget` | `alertOnly: true` and alert thresholds, as fractions of the owner's ceiling | budgets never stop spend, so the lease and the teardown do |
| `exposure` | an external address and its reason, and any ingress (port, protocol, source range, reason) | see the exposure rules below |
| `observer` | the dedicated observer's name, `scope: RUN_PROJECT` (its roles are bound on the run project only), roles from the closed viewer list, `exportedKeys: false`, `payloadFree: true` | the roles can list every class the report counts |
| `credentials` | `inPlan: false`, `heldBy: OWNER` | |
| `teardown` | the run-name prefix, the steps, what the run project may keep (`PROJECT`, `BILLING_LINK`, `AUDIT_LOGS`, `OBSERVER_IDENTITY`), and the observer as the residual checker | the residual always keeps the run project and the observer identity that makes the report |
| `approval` | the owner approves, binding `PLAN_SHA256` | |

The closed viewer list is `roles/compute.viewer`, `roles/logging.viewer`, `roles/monitoring.viewer` and
`roles/iam.securityReviewer`. Every observer holds the first, second and fourth, so it can list each class the report
counts:
- `roles/compute.viewer` lists the fourteen compute and network classes;
- `roles/iam.securityReviewer` lists the buckets, the service accounts, their keys and the project's IAM policy;
- `roles/logging.viewer` reads the audit log that shows which bindings were granted since the lease started.

`roles/monitoring.viewer` is optional.

**Cost rules.**
- The rate card is dated at most 31 days before the plan, and at most 31 days before the lease starts.
- Every price is positive. A SKU appears at most once on the rate card and at most once among the line items; a rate
  card SKU need not have a line item. Each line item uses a rate card SKU and its unit.
- Each amount is quantity × price, within half a cent, and the total is the sum of the amounts, within half a cent.
- The total is at most the owner's ceiling.
- Coverage: for each machine type there is an `hour` line item, whose SKU is the machine type itself, for at least
  count × maximum duration. For each boot-disk SKU there is a `gb-month` line item with that SKU for at least the disks'
  GB × maximum duration ÷ 730. Both allow a shortfall of 0.005 of a unit, the rounding of a quantity to two decimals.
- Other charges, such as an external address or network egress, may be added as line items, but the checker does not
  require them.

**Exposure rules.**
- An external address names its reason, and a plan without one has no reason.
- Each ingress source range is a network address with its prefix.
- In every plan, all the sources together cover at most 65,536 addresses (a /16). The whole internet, or halves of it,
  never pass, and neither does a private /8.
- Without an external address, every source is also an RFC 1918 private network.

A plan's sha256 is taken over its canonical JSON: keys sorted, no whitespace, UTF-8, integral numbers as integers, and
other numbers as Python's `json` module writes them (`0.00001` is `1e-05`). `scripts/lab_run_plan.py` is the reference
for the sha256.

No string anywhere in a plan, lease or report may look like a credential, an account identity or a billing account:
- an `@`;
- a key marker (`-----BEGIN`, `PRIVATE KEY`, `private_key_id`);
- an access-key, token or client-secret prefix anywhere in a string: `AKIA`, `ASIA`, `AIza`, `ya29.`, `1//` and `ghp_`
  with its kind, each followed by at least four token characters; `github_pat_`, `xoxb-` with its kind and `GOCSPX-`
  on their own;
- a service-account domain, in either case;
- a billing-account-shaped id (three groups of six hexadecimal digits joined by hyphens), in either case and anywhere
  in a string.

Each shape has its own negative vector. The run project's id appears in a plan only as `project.id`, and nowhere in its
lease, so the plan id and the lease id that published evidence cites cannot carry it.

### Lease

The lease names the plan id and the plan's canonical sha256, the owner's approval reference, and a start and an expiry
in UTC. The approval reference is an opaque label of the form `OA-…` (upper case), never an identity.

The checker requires that the lease:
- binds this plan's sha256;
- expires after it starts;
- lasts at most the plan's maximum duration;
- starts on or after the plan's preparation date;
- starts at most 31 days after the rate card's date.

A changed plan has another sha256 and needs a new lease.

### Teardown-residual report

The run's own observer reports the plan's run-name prefix and, for each resource class in a fixed order, how many
resources remain after teardown. Each class has its own scope:
- **Every such resource in the run project**, named with the prefix or not, for the fourteen compute and network
  classes: instances, instance groups and instance templates; disks, snapshots and images; addresses, networks,
  subnetworks, firewall rules, routes, routers, NAT gateways and forwarding rules. A default network, or a resource the
  run left unnamed, is counted.
- **Named with the plan's prefix**, for buckets and service accounts.
- **Every user-managed key in the run project**, the observer's own included, for service-account keys.
- **Granted on the run project since the lease started**, for IAM bindings: the Admin Activity audit log shows each
  grant. The observer's own viewer bindings are left out.

The report also states what the project kept, when the teardown completed, when it was observed, and that it is
payload-free.

The checker first checks the lease again, then requires:
- the report bound to this lease and plan, from the run's own observer, counting the plan's prefix;
- every class listed, in order, and zero in every class;
- the kept classes within the plan's residual, always including the run project and the observer identity;
- the teardown completed within the run and before it was observed;
- the observation after the lease expired, so nothing the run could still create goes unseen, and within a day of the
  expiry.

A teardown that completed after the lease expired is refused as a **lease overrun**.

## Runbook

1. **Separate project.** Each run uses a GCP project separate from the old lab foundation, which outlived that lab's
   teardown. The plan declares the separation and the owner confirms it when approving. A run project holds one run at
   a time. Between runs it holds no compute or network resource, so create it without the default network, or delete
   that network before the first run. Between runs its IAM policy holds only the owner's baseline bindings and the
   observer's viewer bindings; the owner confirms this when approving.
2. **Plan.** Prepare a run plan with a rate card dated within 31 days. Every resource the run creates is named with the
   plan's run-name prefix. Check the plan with `plan PLAN`, then send the plan and its sha256 to the owner, through the
   lane monitor. Nothing is applied from CI.
3. **Approval and lease.** The owner approves that sha256 and issues a lease within the plan's maximum duration, starting
   within 31 days of the rate card. The owner holds every credential; no plan, lease, report, repository or session
   carries one.
4. **Run.** Only the plan's workload runs, in the plan's location, with the plan's exposure. Budgets alert at their
   thresholds, fractions of the owner's ceiling, but never stop spend; the lease does. The run's own access ends when
   the lease expires. The run creates resources only of the eighteen classes the report counts. Operator SSH access,
   if any, uses OS Login, so no key is added to the project's metadata.
5. **Teardown.**
   - Before the lease expires, run the plan's teardown steps: delete every compute and network resource in the run
     project, every bucket and service account named with the prefix, and every user-managed key; revoke the bindings
     granted since the lease started, except the observer's own.
   - Then, after the lease expires and within a day of it, the dedicated observer lists every class in its scope,
     read-only and payload-free.
   - Check the report with `teardown PLAN LEASE REPORT`; it must show nothing beyond the plan's residual.
   - After accepting the report, the owner revokes the observer.
6. **Where the documents live.** Real plans, leases and reports carry the real project id. They stay with the owner,
   outside every repository. Published run evidence cites only the plan id, the plan sha256 and the lease id. A refused
   report, or a lease overrun, goes to the owner before any further run.

## Not claimed

- No cloud run, cost or teardown is proven here. The vectors are invented examples, and their prices are not quotes.
- The checker cannot see whether:
  - a project is in fact separate from the lab foundation;
  - an image is in fact public;
  - a reported count is true;
  - the observer's scope, roles, missing keys and revocation are as declared, or the roles in fact list each class
    (that rests on the provider's role definitions);
  - the lease was issued by the owner: its approval reference is an opaque label, not a signature;
  - the rate card's prices match their source.

  The owner's approval, the owner's custody of every credential and the observer's read-only listing are those
  controls.
- Buckets and service accounts outside the run-name prefix are not counted.
- Resource kinds outside the eighteen classes, such as reservations, machine images or serverless services, are not
  counted. Runbook step 4 keeps the run to the counted classes; that it stayed there rests on the owner's review.
- IAM bindings granted before the lease started, and bindings on a resource the project keeps, are not counted. The run
  project's IAM policy between runs rests on the owner's baseline (runbook step 1).
- Only the form of the plan id, the lease id, the approval reference and the observer's name is checked. That they carry
  no person's name and no project id of the organisation rests on the owner's review.
- The project's metadata, such as SSH keys, is not counted; runbook step 4 keeps keys out of it.
- The free-text rule refuses common credential and identity shapes. It cannot prove that a plan carries no secret.
- Charges other than machine-hours and boot disks are not required in the estimate.
- Linux evidence states are unchanged. CONF-LINUX-001 and W06 still need their own runs and evidence.
