# ADR 0009 — separately owned host enforcement prerequisites

Status: accepted planning ownership and design direction under MET-ENFORCE-001;
no runtime ABI amendment, installation grant or qualification.

## Context

The conditional observation/enforcement design requires actual containment and
per-operation admission before a reduced observation schedule can be considered.
The external feasibility screen found no demonstrated drop-in implementation for
the full fixed broker and native qualification contract. The existing R10
Kubernetes controller must not be mistaken for an independently installed host
enforcer or be silently made privileged.

## Decision

R10 (`mas-harness-operator`) is accountable for planned source modules named
host-containment, capacity-broker, policy-observer and effect-admission. Logical
namespaces are `host-enforcement/<module>/`, not dispatchable file permissions.
They have separate artifacts, processes, privileges, state/migrations and failure
states from the nonroot Kubernetes controller. Existing controller responsibilities
and grants do not expand. Deployment still requires independent host authority.

Prefer the existing Linux security primitives and a versioned systemd-delegated
profile for conventional Linux hosts. This direction requires a later explicit
ABI/compatibility amendment. Preserve current fixed role paths and exact BPF
semantics now; no permissive fallback or automatic host installation.

R12 owns independent interface/conformance tests, qualification readers and exact
artifact/native verification. R11 packages released artifacts and offline closure.
R01 remains the authority for any affected public schema. R00 coordinates exact
successor packets and dependency amendments. No new repository or harness.

The independent operation gate must cover reads as well as mutations, already-open
connections, queued requests, urgent invalidation and serialized relevant policy
writers. No success response creates that authority. Concrete mechanism, private
interfaces, language, versions and complete bypass coverage remain blocking W01/W02
work in the [amendment](../alpha-2/ENFORCEMENT_INTEGRATION.md).

## Consequences

This fixes source accountability without claiming an enforcer exists. All twelve
obligations remain OPEN_UNPROVEN. Existing public/native contracts, old task
packets, source-reuse/legal boundaries and budgets stay unchanged. No implementation
may start from this ADR alone; exact file paths, released prerequisites, bounded
acceptance and independent review gates must be published first.

Use upstream implementations for general mechanisms, not a new sandbox kernel.
Do not accept systemd presets, Tetragon presence, Falco alerts, Kubernetes admission
success or signed paperwork as proof of the entire project-specific boundary.
No source/build cycle or imported plane implementation is introduced. Rollback
before consumption is a reviewed source revert; afterwards use a compatible
successor without resetting history or consumed authority.
