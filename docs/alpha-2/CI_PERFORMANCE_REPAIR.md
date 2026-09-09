# Alpha 2 — MET-PERF-001: bounded YAML parsing cost repair

Approved 2026-09-09. Independent prerequisite from meta main
7447acd1a0471cecb79da36abe6b4ff0859f0a92; one packet, branch and PR.
The publication has 139 packets, thirteen repositories, four planes and sixteen
harnesses. It does not contain or close unmerged MET-REPAIR-012 / PR106.

## Evidence and diagnosis

The credential-lifecycle branch d78ef832cb5ad9b7b16074ab39b5b2bfec36f7d1
passed eighteen local commands, 2408 tests and ten existing isolation skips.
Its nested replay took 411.23 seconds and outer pytest took 845.50 seconds.
CI34297208371 attempt one failed the unchanged 420-second nested replay bound;
2407 other tests passed. The sole unchanged retry reached the root launcher's
900-second limit before a final test summary. Both failure logs remain retained:

- Attempt one: a9fe028fb7c4c1c56b9d44324e4b0cea12156d7d9375d49ab3537be839eece5b.
- Attempt two: 7a039daf67e188fe529113f1988ae857d8cd77e7962744a8c0879f49fcfdbe79.

The complete current non-Linux-runner suite runs once inside the predecessor
test and again in outer pytest. Both independent replays remain mandatory.
Repeated safe YAML construction was investigated without running unisolated code.
Diagnostic commit 570f72ebee9d603233a80478b25c2f1bbaaa0aeb ran only the
declared fixed-corpus measurement under signed activation105. It is DIAGNOSTIC_ONLY,
not full packet acceptance. Its log SHA256 is
1ef8a9636f16f3feabacdd8af63744e2961f4eae437f4ceec195bb4ecb3807dc.

The pinned PyYAML6.0.2 already contains LibYAML on this development workstation.
For 155 YAML files / 5517070 bytes, Python safe parsing took 5690761759 ns
and LibYAML safe parsing took 1932461548 ns (about 2.94 times faster).
The 139 packet files alone took 802323928 versus 75403002 ns (about 10.6 times).
Typed values, mapping order, aliases and cycles matched for every measured file.
This isolates parsing cost, not the whole CI root cause or future timing stability.

## Exact implementation boundary

- Select only PyYAML's existing CSafeLoader when installed; otherwise preserve
  its SafeLoader fallback. Both use the safe constructor and resolver. No new
  wheel, native build, dependency, environment flag or user-selectable loader.
- Use an explicit local helper at the declared validator and test-fixture call
  sites. Do not monkeypatch yaml.safe_load or any third-party/global module.
- Every call rereads its source where it did before and constructs fresh objects.
  No pathname/mtime cache, mutable parsed-object sharing or cached acceptance.
- Preserve the stricter duplicate-key constructors in architecture, readiness
  and reuse validation, including merge-key flattening. No unsafe loader or
  executable tag is admitted. The zero-bill scanner and release-lock checker
  remain byte-identical and are independently exercised by their existing tests.
- Protect complete previous test source. Permitted substitutions are only the
  explicit safe-parser import/call references and current catalog count 138 to
  139. Every assertion, parameter vector, test identity, marker, suite root and
  collection behavior otherwise remains byte-identical. New tests are separate.
- No change to the nested replay implementation, its 420-second timeout, outer
  trusted 900-second timeout, fifteen-minute workflow, locked toolchain, root
  policy, network isolation, warm-source denial or billing controls.

The immutable authority pins all 138 predecessor YAML and original architecture,
legal, policy, release and schema inputs, plus replay/runner/test/configuration
controls. The separate before-test data is never imported or executed.
Its byte reconstruction guard and negative tests reject removed or changed old
assertions, narrowed parameter sets, new skip markers and collection changes.

Independent regressions compare Python, LibYAML and the selected helper across
the fixed corpus and scalar/tag/alias/merge/Unicode/stream cases; unsafe tags,
duplicate mappings and malformed documents stay rejected. Fresh parsing and
pure-Python fallback are explicit tests. Native presence and measured timings
are reported, not converted into a portable wall-clock performance guarantee.

## Acceptance and successor sequencing

Final acceptance declares nineteen direct-argv commands in one signed isolated
tree: fixed-corpus measurement, all fifteen current validators, performance
authority validation, the unchanged complete pytest command and zero-bill scan.
The diagnostic one-command draft is not a substitute for those nineteen commands.
Required PR CI, merge and independent local exact-main remain separate gates.
Retain failures and allow at most one unchanged retry per failed verification
stage. Never increase limits, omit coverage or reduce isolation to obtain green.

| Phase | ID / gate | Publication status | Description |
|---|---|---|---|
| Phase 0 / Alpha 1 | Foundations | DONE — recorded source/offline | Live acceptance separate |
| Alpha 2 | MET-PERF-001 | ONGOING | Independent parsing repair and full replay gates |
| Alpha 2 | MET-REPAIR-012 / PR106 | WAITING | Separate draft, failed CI preserved |
| Alpha 2 | CONF-FIX-005 | WAITING | Product credential correction after accepted authority |
| Alpha 2 | CONF-LIVE-003/004/005/006 | WAITING | Proxy, probes, packaging, integration |
| Alpha 2 | Native Linux AMD64 / ARM64 | NOT_RUN_ENV_UNAVAILABLE | Independent native qualification |
| Alpha 3 / Alpha 4 | Governed actions / enterprise matrix | WAITING | Existing roadmap unchanged |

After this packet closes, a separate MET-REPAIR-012 run must reconcile its
unpublished authority, dependency edge, catalog count, parser call sites and
mechanical preservation guards with accepted performance main. Validate exact
old and new packet identities; do not add a blanket future-file or hash exemption.
Do not edit that branch, merge it, start CONF-FIX-005 or claim its CI fixed here.
The later performance comparison must use that later source's fresh results.

Before consumption revert this independent packet as one reviewed unit. After
consumption use a bounded successor and preserve every historical input, failed
log, signer history and tenant data. No product edits, warm-source access, live
requests, root installation, administrator prompt, hosted runner, downloads,
artifact uploads, cloud provisioning, paid API or billable capacity are needed.
Alpha 2 remains ONGOING; model-effort transition NOT_DUE.
