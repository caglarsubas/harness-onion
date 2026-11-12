# Repository Plan: `mas-harness-reference-lab`

## Purpose and boundaries

R14 is the programme's reference-estate repository: synthetic test doubles of a client's side (infrastructure, services
and data), banking first. It owns the `reference/**` estates and mocks; a campaign input, never a gate.

Non-goals:

- No production, customer or personal data: every record is synthetic, opaque and guarded against real identifiers.
- No product code, task packets, roadmap writes or contracts; nothing another repository imports.

## Testing, verification, and acceptance

Offline acceptance is ordered `python3 -I -B` argv arrays over the standard library; no network, no hosted runner.

Its first packet will declare `prefetchCommands: []` and ordered `offlineAcceptanceCommands` of such argv arrays; the
executor supplies the hash-pinned packet through `HARNESS_TASK_PACKET` and invokes only
`offlineExecution.wrapperArgv: ["./ci/verify-offline.sh"]` for the complete ordered list. No packet of this repository
is published at slot 288 (MET-007 registers it), so nothing here is verified yet.

## Repository structure and exact tree

This tree projects the current task-packet `allowedPaths`. No packet names this repository at slot 288, so the tree
lists no root entry; the first packet's `allowedPaths` (the `reference/**` estates and mocks) add its roots.

```text
mas-harness-reference-lab/
```

## Dependencies

- Contract/source: none. The estates read other repositories through git-archive exports at pinned commits; nothing is
  imported.
- Build artifact: none; the acceptance set is the standard library.
- Runtime integration: none. The estates are campaign inputs for other repositories' runs, never a gate and never a
  dependency edge.

## Warm-source mapping

None. The repository holds no warm source and no reuse index entry.

## PR packets

None at slot 288. R14 is registered by MET-007 (kind meta, releaseSet EXCLUDED) without a packet; its first packet,
REF-ESTATE-001, needs the bundle v8 route and removes all three registered-without-packet exemptions:
tests/test_task_packets.py, tests/test_packet_declaration_consistency.py and scripts/validate_readiness.py.

## Release and rollback

No release artifact. A merge is the publication. Rollback is the revert of the PR.

## Zero-bill rules

No file under `.github/`; no hosted runner, Actions cache, artifact or package; no network in acceptance; the owner's
verifier is the only CI.
