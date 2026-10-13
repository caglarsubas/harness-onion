# Research adoption v2: the October 2026 MAS-harness corpus (MAS-RA-000)

Alpha 2A; checked 2026-10-12. Evidence class `META_PLANNING_ONLY`: data only, no public contract, selector, catalog, policy or runtime change.

`crosswalk.json` (`planeon.internal.research-adoption/v2`) is the successor overlay of `architecture/research-adoption.json` (`planeon.internal.research-adoption/v1`, MET-ADOPT-002, sha256 `18dadbbe9aa29b69d18b9ded27e27f6057cf03b437190d14477b2c6908dbc5d5`) and of `docs/alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md` (sha256 `f6a891e8bdbcc579e60800773addd70ca29a2c4021c2dc95af62be93e91f061d`). Both stay byte-identical, because later records pin them by digest, and they remain the record of the 2026-09 corpus, the sixteen harness adoption targets, the gates G1-G8 and the policies; the policies are carried over unchanged. This record adds the October 2026 corpus (three research syntheses, eight seed papers read in full, eleven secondary papers, five standards and the codebases they name) and maps it onto the same sixteen harnesses. This README is the map's successor text and is generated from the record; `scripts/research_adoption_v2.py` checks both.

SUCCESSOR_OVERLAY: the predecessor and its map stay byte-identical and remain the record of the 2026-09 corpus, the sixteen harness adoption targets, the gates G1-G8 and the policies; this record adds the 2026-10 corpus and maps it onto the same sixteen harnesses. The carried policies govern validation, which stays offline; the codebase metadata comes from the one owner-approved build-time re-check (Q-RA1).

## Definitions

| Reuse mode | Meaning |
|---|---|
| REFERENCE_DESIGN | Read for contract and test design; no code reuse planned. |
| VENDOR_CANDIDATE | Candidate pinned package or vendored module, admitted only through gates G1-G8 at packet time. |
| PLANNED_BASELINE | Already a planned baseline or 'later' option in HARNESS_PAPER_REPOSITORY_MAP.md. |
| TEST_ORACLE_CANDIDATE | Benchmark, task format or fixture source for R12 campaigns. |
| LICENSE_BLOCKED | No OSI licence, no licence file or NOASSERTION at check time: design reference at most, unreleasable under the legal policy until clarified. Takes precedence over REFERENCE_DESIGN: a reference design keeps that mode only when its licence outcome is default-allowed, an allowed exception or open content. An index or a planned baseline keeps its mode whatever the licence, and its licence ceiling binds. |
| INDEX_ONLY | Curated list used to find sources; nothing to reuse. |
| NOT_RETRIEVABLE | Named by a paper, but the repository was not found on 2026-10-12. |
| NOT_APPLICABLE | No open repository (closed system, hosted service or paper only); pattern reference only. |

| Alignment | Meaning |
|---|---|
| ADOPTION_CANDIDATE | The paper links to a codebase whose reuse mode is VENDOR_CANDIDATE; the codebase may be proposed as a pinned package through gates G1-G8. |
| CONCEPTUAL_ALIGNMENT | The paper informs a contract or design here; no codebase of it is proposed for reuse. |

| Licence ceiling | Meaning |
|---|---|
| REUSE_AFTER_GATES | The GitHub-reported licence is default-allowed (or an allowed exception) under the policy; reuse still needs a pinned artifact, its licence review and gates G1-G8. Not a clearance. The ceiling binds whatever the reuse mode. |
| DESIGN_REFERENCE_ONLY | The licence outcome allows nothing beyond reading the design here: unresolved, missing, denied, unknown, review-required, open content (non-code content only, not reused by this record) or no repository. |

| Licence-policy outcome | Meaning |
|---|---|
| DEFAULT_ALLOWED | On the policy's defaultAllowedSpdx list. |
| ALLOWED_EXCEPTION_EXPRESSION | On the policy's allowedExceptionExpressions list. |
| OPEN_CONTENT | On the policy's openContentSpdx list: non-code content only. |
| OPTIONAL_EXPLICIT_REVIEW | On the policy's optionalExplicitReview list: release denied without a decision. |
| PLANNED_UNRESOLVED | NOASSERTION: a planned placeholder only, release denied. |
| DENIED | On the policy's deniedForDefaultDistribution list. |
| DENY_MISSING_LICENSE | GitHub reports no licence; a null licence in a roadmap or packet check means no SPDX identifier was reported. |
| DENY_UNKNOWN_LICENSE | An identifier on none of the policy's lists. |
| NOT_RETRIEVABLE | The named repository was not found at the re-check. |
| NO_REPOSITORY | No open repository is named (a closed system, hosted service or paper only). |

| Claim kind | Meaning |
|---|---|
| SYNTHESIS_CLAIM | A claim one of the syntheses made about the paper. |
| AVAILABILITY_CHECK | Whether the paper states code, data or a licence; NOT_FOUND means it does not. |
| VENUE_CHECK | The paper's venue and version as printed. |

| Claim status | Meaning |
|---|---|
| VERIFIED | The paper supports the claim as stated; qualifications are given in the finding. |
| CORRECTED | The paper supports a materially different figure, list or scope, given in the finding. |
| NOT_FOUND | The paper does not state it (used for availability checks only). |

Secondary papers are named as in RS-CLAUDE Part A (the related-work map); their short names avoid author names.

## Decisions

| Decision | Selected | By | Text |
|---|---|---|---|
| Q-RA1 | a | owner (via the lane monitor) | One read-only pass: 41 unauthenticated requests (git ls-remote HEAD + public GitHub repo API), generic User-Agent, no personal data, no downloads; results recorded with the check date. Conditions: no token or auth header, no account names or email in any URL, header or User-Agent, PAUSE prefix on every command if an agent runs it. |
| Q-RA2 | a | owner (via the lane monitor) | Digests + derived data: the syntheses and the eight arXiv PDFs referenced by sha256 only (as MET-ADOPT-002 did); grounding facts with page numbers embedded as derived data in crosswalk.json; no vendored grounding JSONs. |
| HO-D1 | - | roadmap session at the owner's request | HO-D1 (2026-10-12, roadmap session at the owner's request): the MAS-RA ratings are not re-rated downward; Score stays a value-per-effort measure. Execution order is a separate rule: in-flight work (HE-002 PR, W04-2) ships first, and the roadmap's Next-up now shows in-progress work before ready work. |
| HO-D2 | - | roadmap session at the owner's request | HO-D2 (2026-10-12): MAS-RA-002 becomes a dependency of CONF-WG-001 (its configuration-level record is the 'qualified baseline' format) and MAS-RA-008 becomes a dependency of CONF-A3-001 (it specifies the tool receipt, outcome review and bounded-retry behaviour that gate already names). MAS-RA-004, MAS-RA-009 and MAS-RA-010 stay inputs, not gates: the multi-agent organization layer is outside the v1.0 scope statement (alpha to GA), so they wait for an explicit scope decision at Beta 2 planning. |
| HO-D3 | - | roadmap session at the owner's request | HO-D3 (2026-10-12): the primary lane builds MAS-RA-000 as harness-onion slot 228, right after the HE-002 PR is pushed (while HE-002 is in review and verify). Reasons: it is a data-only meta packet with no W03/W04 content; the primary lane built the three most recent harness-onion packets and holds the current mechanics; R10 verifies take 30 s, so the primary lane has verifier headroom, while the parallel lane's R12 runs take about 420 s each. |

## Sources

The three syntheses are user research inputs, not execution authority, and are referenced by sha256 only.

| Id | File | sha256 | Summary |
|---|---|---|---|
| RS-GPT | mas-harness-research-gpt.md | `5fcb877665c5d9b240d306c4d55745761c31b6458825fde41a4bd661cd73f9c3` | Five planes (definition, execution, assurance, evidence, improvement); canonical APIs and domain objects (AgentSpec, TopologySpec, ScenarioSpec, RunEvent, Verdict, RunManifest); layered testing model; CI/CD pipeline; eight security invariants; milestone roadmap and technology profiles. |
| RS-GEMINI | mas-harness-research-gemini.md | `00363eb38bfa0b0cfd02f1ea16a582d91e0965d528a72be6e7e0641f84fa1016` | ETCLOVG taxonomy (execution, tools, context, lifecycle, observability, verification, governance); five production failure modes; DASH six-layer architecture (code-as-harness substrate, decentralized grid, state engine, deterministic gates, JIT synthesis and evolution, distillation). |
| RS-CLAUDE | mas-harness-research-claude.md | `c3f8aa7180c31c43ad25fdf564df218e1cc53ba09377d20ce1d2edbe409edc34` | Related-work map with verification marks; eight-layer reference architecture L1-L8; 13 design principles with counter-evidence; one-page blueprint; critique of harness-evolution claims (matched-budget, held-out, cross-model); recommendation to report (model, harness, budget, agent count). |

## Priority rule

Verification and evidence contracts (L4, L8) come first, then the loop and tool gateway (L1, L7), coordination (L3) and shared state (L2); the improvement plane (L5) and distillation (L6) are gated by MAS-RA-005 and ranked last, because the reported held-out gains are small (+0.6 points) and unstable, and because spending verification compute before evolution compute is the syntheses' shared recommendation.

## Eight layers to the sixteen harnesses

| Layer | Question | Harnesses | Items | Evidence |
|---|---|---|---|---|
| L1 Core loop and action primitives | What can one step express? | H10 `execution.orchestration`, H11 `execution.tool-skill-sandbox` | MAS-RA-008 | JAZ invoke and RLM recursion; CodeAct; 13 hook events over invoke, LLM query and REPL exec with local and dynamic scope; StuLife far-recall 69.9 vs Letta 61.8 at 43% of the cost; an uncapped run reached depth 70 (JAZ pp. 4-7, 14). A reproduction of RLM reports depth-2 recursion cutting accuracy (secondary). |
| L2 State, context and memory | What persists, where, and who can read it? | H8 `knowledge.memory-state`, H7 `knowledge.retrieval-context` | MAS-RA-009 | Typed boards (Agensh: OBSERVED, FACT, FAIL, CLAIM, PATCH_SUMMARY, capped entries, grep over history), verified gists (DeLM, secondary), ACE playbooks (secondary), history as a first-class variable passed by reference (JAZ); context clash and poisoning are the named failure modes. |
| L3 Topology and coordination | Who decides what, and how do agents meet? | H10 `execution.orchestration`, H9 `execution.protocol-interoperability` | MAS-RA-004 | Agensh scales 1 to 1,024 agents without an orchestrator (pandoc 33.89% to 55.06%; means over the five hardest ProgramBench instances); HERMES directed typed messages and single-writer rule; MASS topology as an integer block vector under an agent budget; the agent-scaling study (2512.08296) +80.8% to -70.0% and MAST 37% inter-agent misalignment are secondary. |
| L4 Verification, adjudication and revision | How is the final answer chosen and repaired? | H16 `trust.evaluation-assurance`, H13 `trust.security-safety` | MAS-RA-001 | VeriHarness: 34% of unanimous claims wrong, 74% of disagreements hold the right alternative (Opus 4.8 on APEX-Agents, 1,692 claims); claim-check-evidence-verdict records with an unresolved state; HERMES: deterministic failures can never be PASS; HarnessDev: self-reported status is never a scoring input. |
| L5 Optimizing the harness itself | What is searched, and by whom? | H16 `trust.evaluation-assurance`, H14 `trust.governance-agentops` | MAS-RA-005, MAS-RA-006 | MASS block-first optimization (largest stage gain +6); MILO dominance admission with held-out re-scoring but headline numbers include the search split; HarnessDev: 2 clear positives in 64 switches, held-out optimal 2 of 9, fixed-executor regressions to -10.32; the harness-evolution evaluation (2607.12227) +0.6 and AHE 11.6% are secondary. |
| L6 Distillation and co-evolution with weights | What moves into weights, and what stays external? | H2 `runtime.model-inference`, H12 `execution.ml-decision` | MAS-RA-007 | Harness-Zero: 23.3% to 44.3% macro average for a 9B student under a single-tool harness; per-pattern recovery 40-100%; USPTO trails the source harness; guards survive only as learned behaviour; OPHSD, EvoHarness-RL and WHALE are secondary. |
| L7 Governance, safety and economics | What bounds the system? | H13 `trust.security-safety`, H14 `trust.governance-agentops`, H15 `trust.observability-finops`, H11 `execution.tool-skill-sandbox` | MAS-RA-008, MAS-RA-005, MAS-RA-010 | JAZ budgets, iteration, recursion and context-window hooks; HERMES revision budget B (default 3, returns beyond 3 at most 0.9 points); HarnessDev 500-step and 7,200 s caps with a liveness guard; VeriHarness read-only workspace and information boundary; SLSA/Sigstore provenance and Anthropic's multiagent findings are secondary. |
| L8 Evaluation and benchmarks | What is the unit of evaluation? | H16 `trust.evaluation-assurance`, H15 `trust.observability-finops` | MAS-RA-002, MAS-RA-003, MAS-RA-000 | Report (model, harness, budget, agent count); HarnessDev 2,207 instances over five benchmarks with avg@3, a ±4.75-point noise band and executor tokens beside score; MILO k=3 rollouts and task-clustered CIs; VeriHarness three verifier seeds and judge-drift control; JAZ distinct cache key per run; Harness-Bench is secondary. |

| Harness | Layers | MAS-RA items (P primary, S secondary) | Papers | Codebases | Standards |
|---|---|---|---|---|---|
| H1 `runtime.infrastructure` | - | - | - | gitea | - |
| H2 `runtime.model-inference` | L6 | MAS-RA-002 S, MAS-RA-007 P | Harness-Zero | harness-zero, ophsd, whale | - |
| H3 `runtime.ai-gateway` | - | - | HERMES | - | - |
| H4 `runtime.experience` | - | - | - | - | - |
| H5 `knowledge.domain-semantic` | - | - | - | - | - |
| H6 `knowledge.data-integration` | - | - | - | - | - |
| H7 `knowledge.retrieval-context` | L2 | MAS-RA-009 S | - | - | - |
| H8 `knowledge.memory-state` | L2 | MAS-RA-004 S, MAS-RA-009 P | Agensh, RLM, DeLM | agensh, delm, deepagents, reasoning-bank, letta | - |
| H9 `execution.protocol-interoperability` | L3 | MAS-RA-004 S | Agensh | - | MCP, A2A |
| H10 `execution.orchestration` | L1, L3 | MAS-RA-003 S, MAS-RA-004 P, MAS-RA-006 S, MAS-RA-008 P, MAS-RA-009 S, MAS-RA-010 S | HERMES, JAZ, Agensh, HarnessDev, MASS, RLM, DeLM, Agent scaling, AggAgent | mini-swe-agent, openhands, agensh, delm, agent-scaling, claudes-c-compiler, langgraph, agent-framework, crewai, gitea, mattermost, jaz, rlm, codex, smolagents, deepagents, stripe-minions, camel | - |
| H11 `execution.tool-skill-sandbox` | L1, L7 | MAS-RA-006 S, MAS-RA-008 P, MAS-RA-010 S | HERMES, JAZ | openhands, jaz, codex, smolagents, swe-rex, e2b | MCP |
| H12 `execution.ml-decision` | L6 | MAS-RA-007 P | Harness-Zero | harness-zero, ophsd, whale | - |
| H13 `trust.security-safety` | L4, L7 | MAS-RA-001 S, MAS-RA-004 S, MAS-RA-005 S, MAS-RA-008 S, MAS-RA-009 S, MAS-RA-010 S | VeriHarness | promptfoo, codex | - |
| H14 `trust.governance-agentops` | L5, L7 | MAS-RA-005 P, MAS-RA-006 S, MAS-RA-007 S | MILO, Harness-Zero, Meta-Harness, AHE, Self-Harness, Evolution evaluation | meta-harness, ahe, self-harness | SLSA, SIGSTORE |
| H15 `trust.observability-finops` | L7, L8 | MAS-RA-001 S, MAS-RA-002 S, MAS-RA-003 P, MAS-RA-006 S, MAS-RA-008 S | VeriHarness, JAZ, MAST | phoenix, langfuse, openhands | OTEL-GENAI |
| H16 `trust.evaluation-assurance` | L4, L5, L8 | MAS-RA-001 P, MAS-RA-002 P, MAS-RA-003 S, MAS-RA-005 S, MAS-RA-006 P, MAS-RA-007 S, MAS-RA-010 P | VeriHarness, MILO, HarnessDev, MASS, Meta-Harness, AHE, Self-Harness, MAST, Agent scaling, Harness-Bench, Evolution evaluation, LLM-as-a-Verifier, AggAgent | veriharness, aggagent, llm-as-a-verifier, harbor, agent-scaling, meta-harness, ahe, self-harness, promptfoo, gepa, dspy, aflow, adas, openevolve, stripe-minions, camel, jit-agent-darwinx, awesome-agent-harness, awesome-harness-engineering, awesome-code-as-harness, awesome-agent-evolution, harnessdev, milo-listings | - |

## Design principles and their counter-evidence

| Id | Principle | Counter-evidence or cost |
|---|---|---|
| P1 | Minimal primitives, maximal expressivity: delegation, memory and self-improvement are programs over one recursive primitive | depth-2 overthinking; unstructured flexibility breeds specification failures |
| P2 | Separate harness from model, but measure the pairing | evolved harnesses transfer weakly across models |
| P3 | Evidence over consensus; investigate in separate contexts; adjudicate fresh | N rollouts plus investigation |
| P4 | Match topology to task structure | Agensh still gains to 1,024 agents on decomposable work |
| P5 | For wide, decomposable work, self-organize over shared infrastructure rather than route through one main agent | turf wars under conflicting objectives |
| P6 | Verify before admitting to shared state | cost grows with team size |
| P7 | Optimize locally and globally, interleaved | search cost |
| P8 | Search the whole harness and the search strategy; keep negative evidence and full traces | agents mispredict their own regressions |
| P9 | Evolve on development tasks, gate on held-out, compare to matched-budget sampling, red-team for shortcuts | fair protocols shrink headline gains |
| P10 | Distill procedural behaviour; keep knowledge-heavy or volatile capability external | distillation is domain-specific |
| P11 | Allocate models heterogeneously by role | weak workers raise verification load |
| P12 | Govern through hooks and budgets, not prompts | hooks do not solve incentive conflicts |
| P13 | Design for caching and incremental contexts | recursion and branching fragment caches |

## Critique evidence that sets the priorities

| Id | Paper | Source class | Figure | Consequence |
|---|---|---|---|---|
| CE-1 | Evolution evaluation (2607.12227) | SECONDARY_AS_REPORTED | Harness evolution gains only +0.6 points on held-out tasks and does not consistently beat matched-budget parallel sampling (2607.12227, as reported by RS-CLAUDE). | Evolution waits behind the admission gate (MAS-RA-005): held-out split, matched-budget baseline. |
| CE-2 | AHE (2604.25850) | SECONDARY_AS_REPORTED | AHE's per-edit regression predictions: 5 of 43 predicted regressions materialized, a precision of 11.6% (as reported by RS-CLAUDE). | An agent's own regression forecast is not admission evidence; keep negative evidence and full traces (P8). |
| CE-3 | HarnessDev (2609.01437) | SEED_FULL_TEXT | HarnessDev: feedback-pair gains of +3.0 to +13.9 shrink to +1.43 to +4.44 on the held-out 630; under the fixed Gemini executor only one of four lineages (Opus, +2.70) improves held-out and the other three regress, down to -10.32; of 64 version switches only 2 are clear positives (pp. 1, 11-13). | Evolution is unstable and transfers weakly across models: report (model, harness, budget, agent count) and gate on held-out distributions (MAS-RA-002, MAS-RA-005). |
| CE-4 | VeriHarness (2610.00972) | SEED_FULL_TEXT | VeriHarness: 34% of unanimous claims were wrong and 74% of disputed claims contained a correct candidate (Claude Opus 4.8 on APEX-Agents, 434 tasks; pp. 2, 4, 19). | Evidence over consensus: verdicts carry evidence references and adjudication runs in separate contexts (MAS-RA-001, P3). |

## Seed papers (read in full on 2026-10-12)

Each seed paper's checks are of three kinds: the claims the syntheses made about it, whether code, data or a licence is available, and its venue. `crosswalk.json` carries every check with its kind, status and pages, the grounded facts and the contract implications (derived data, Q-RA2).

| Paper | Layers | Harnesses | Items | Alignment | Synthesis claims (V / C / NF) | Availability (V / NF) | Venue | Codebases |
|---|---|---|---|---|---|---|---|---|
| HERMES [2610.07832](https://arxiv.org/abs/2610.07832) | L1, L3, L7 | H10, H11, H3 | MAS-RA-008, MAS-RA-004, MAS-RA-001, MAS-RA-003 | CONCEPTUAL_ALIGNMENT | 4 / 1 / 0 | 0 / 1 | 0 | - |
| VeriHarness [2610.00972](https://arxiv.org/abs/2610.00972) | L4, L2, L7 | H16, H13, H15 | MAS-RA-001, MAS-RA-002, MAS-RA-003, MAS-RA-005, MAS-RA-009 | ADOPTION_CANDIDATE | 8 / 0 / 0 | 1 / 0 | 0 | veriharness |
| MILO [2609.38349](https://arxiv.org/abs/2609.38349) | L5, L8 | H16, H14 | MAS-RA-005, MAS-RA-006, MAS-RA-002 | CONCEPTUAL_ALIGNMENT | 6 / 0 / 0 | 0 / 1 | 0 | milo-listings |
| JAZ [2609.26891](https://arxiv.org/abs/2609.26891) | L1, L2, L7 | H10, H11, H15 | MAS-RA-008, MAS-RA-009, MAS-RA-003, MAS-RA-002 | CONCEPTUAL_ALIGNMENT | 4 / 1 / 0 | 1 / 0 | 0 | jaz |
| Agensh [2609.26781](https://arxiv.org/abs/2609.26781) | L2, L3, L8 | H10, H8, H9 | MAS-RA-004, MAS-RA-009, MAS-RA-010, MAS-RA-003 | CONCEPTUAL_ALIGNMENT | 5 / 1 / 0 | 1 / 1 | 0 | agensh |
| Harness-Zero [2609.24974](https://arxiv.org/abs/2609.24974) | L6 | H2, H12, H14 | MAS-RA-007, MAS-RA-005, MAS-RA-008 | CONCEPTUAL_ALIGNMENT | 6 / 0 / 0 | 1 / 1 | 0 | harness-zero |
| HarnessDev [2609.01437](https://arxiv.org/abs/2609.01437) | L5, L8, L1 | H16, H10 | MAS-RA-002, MAS-RA-005, MAS-RA-008, MAS-RA-003, MAS-RA-010 | CONCEPTUAL_ALIGNMENT | 6 / 1 / 0 | 0 / 1 | 0 | harnessdev |
| MASS [2502.02533](https://arxiv.org/abs/2502.02533) | L3, L5 | H10, H16 | MAS-RA-004, MAS-RA-006, MAS-RA-005 | CONCEPTUAL_ALIGNMENT | 6 / 0 / 0 | 0 / 1 | 1 | - |

| Paper | Status | Licence stated in the paper |
|---|---|---|
| HERMES | arXiv 2610.07832v1 [cs.SE], 6 Oct 2026; preprint; no venue named in the 30 pages. | no |
| VeriHarness | arXiv 2610.00972v1 [cs.AI], 1 Oct 2026; no peer-reviewed venue stated; code and dataset links in Appendix E (p.22). | no |
| MILO | arXiv 2609.38349v1 [cs.LG], 29 Sep 2026; no venue stated. | no |
| JAZ | arXiv 2609.26891v1 [cs.AI], 22 Sep 2026; preprint; no venue named. | no |
| Agensh | arXiv 2609.26781v1 [cs.CL], 22 Sep 2026; technical report; no peer-reviewed venue stated. | no |
| Harness-Zero | arXiv 2609.24974v1 [cs.AI], submitted 21 Sep 2026; no venue stated. | no |
| HarnessDev | arXiv 2609.01437v1 [cs.SE], submitted 1 Sep 2026; not peer reviewed. | no |
| MASS | ICLR 2026 (footnote, p.1); arXiv 2502.02533v2, 31 Jan 2026. | no |

## Secondary corpus (as reported by the syntheses)

| Paper | Name | Layers | Harnesses | Items | Alignment | Reported |
|---|---|---|---|---|---|---|
| Meta-Harness [2603.28052](https://arxiv.org/abs/2603.28052) | Meta-Harness | L5 | H16, H14 | MAS-RA-005, MAS-RA-006 | CONCEPTUAL_ALIGNMENT | Full-trace filesystem proposer over prior code, traces and scores; +7.7 over ACE with 4x fewer context tokens (as reported by RS-CLAUDE). |
| AHE [2604.25850](https://arxiv.org/abs/2604.25850) | Agentic Harness Engineering (AHE) | L5 | H16, H14 | MAS-RA-005, MAS-RA-006 | CONCEPTUAL_ALIGNMENT | Edits as falsifiable per-edit predictions; only 5 of 43 predicted regressions materialized (11.6% regression-prediction precision, as reported by RS-CLAUDE). |
| Self-Harness [2606.09498](https://arxiv.org/abs/2606.09498) | Self-Harness | L5 | H16, H14 | MAS-RA-005 | CONCEPTUAL_ALIGNMENT | The same fixed model mines its own weaknesses, proposes bounded edits and regression-gates on held-in and held-out tasks (as reported by RS-CLAUDE). |
| RLM [2512.24601](https://arxiv.org/abs/2512.24601) | Recursive Language Models | L1, L2 | H10, H8 | MAS-RA-008 | CONCEPTUAL_ALIGNMENT | Prompt as a REPL variable with recursive self-calls; a reproduction (2603.02615) reports depth-2 recursion cutting accuracy (as reported by RS-CLAUDE). |
| DeLM [2606.10662](https://arxiv.org/abs/2606.10662) | DeLM: Decentralized MAS with Shared Context | L2, L3 | H8, H10 | MAS-RA-004, MAS-RA-009 | CONCEPTUAL_ALIGNMENT | Shared verified context of compressed gists plus a task queue replaces the main agent; the 65.7% SWE-bench Verified figure comes from an announcement, not the paper (as reported by RS-CLAUDE). |
| MAST [2503.13657](https://arxiv.org/abs/2503.13657) | Why Do Multi-Agent LLM Systems Fail? (MAST) | L7, L8 | H15, H16 | MAS-RA-003, MAS-RA-004, MAS-RA-010 | CONCEPTUAL_ALIGNMENT | 14 failure modes in 3 categories (specification about 41.8%, inter-agent misalignment about 36.9%, verification about 21.3%) over 1,600+ traces (as reported by RS-CLAUDE). |
| Agent scaling [2512.08296](https://arxiv.org/abs/2512.08296) | Towards a Science of Scaling Agent Systems | L3, L8 | H10, H16 | MAS-RA-004 | CONCEPTUAL_ALIGNMENT | 260 configurations; multi-agent change from +80.8% (decomposable work) to -70.0% (sequential planning) against a single agent (v3 abstract, as reported by RS-CLAUDE). |
| Harness-Bench [2605.27922](https://arxiv.org/abs/2605.27922) | Harness-Bench | L8 | H16 | MAS-RA-002 | CONCEPTUAL_ALIGNMENT | 106 sandboxed tasks and 5,194 trajectories; large variation across model-harness pairings (as reported by RS-CLAUDE). |
| Evolution evaluation [2607.12227](https://arxiv.org/abs/2607.12227) | Rethinking the Evaluation of Harness Evolution | L5, L8 | H16, H14 | MAS-RA-005 | CONCEPTUAL_ALIGNMENT | Harness evolution does not consistently beat matched-budget parallel sampling; held-out gain +0.6 points (as reported by RS-CLAUDE). |
| LLM-as-a-Verifier [2607.05391](https://arxiv.org/abs/2607.05391) | LLM-as-a-Verifier | L4 | H16 | MAS-RA-001 | CONCEPTUAL_ALIGNMENT | Continuous scores from score-token logit expectations; 86.5% on Terminal-Bench V2 and 78.2% on SWE-bench Verified (as reported by RS-CLAUDE). |
| AggAgent [2604.11753](https://arxiv.org/abs/2604.11753) | Agentic Aggregation (AggAgent) | L3, L4 | H16, H10 | MAS-RA-001 | CONCEPTUAL_ALIGNMENT | An aggregator agent explores K parallel rollouts as an environment and cross-checks tool evidence (as reported by RS-CLAUDE; venue not verified there). |

## Standards

| Standard | Layers | Harnesses | Items | Role |
|---|---|---|---|---|
| [Model Context Protocol](https://modelcontextprotocol.io) | L1, L7 | H9, H11 | MAS-RA-003, MAS-RA-004, MAS-RA-008 | Adapter surface at the agent-to-tool edge, behind the tool gateway (MAS-RA-008); not the internal event model. |
| [Agent2Agent protocol](https://a2a-protocol.org) | L3 | H9 | MAS-RA-003, MAS-RA-004 | Edge protocol for externally addressable agent organisations; the internal run-event model stays canonical. |
| [OpenTelemetry semantic conventions for generative AI](https://opentelemetry.io/docs/specs/semconv/gen-ai/) | L8 | H15 | MAS-RA-003 | Neutral trace and metric attribute mapping for run events (MAS-RA-003); no vendor trace schema. |
| [Supply-chain Levels for Software Artifacts](https://slsa.dev) | L7 | H14 | - | Provenance model for content-addressed runtime images and released harness bundles (named by RS-GPT); no MAS-RA item names it yet. |
| [Sigstore](https://www.sigstore.dev) | L7 | H14 | - | Signing and transparency for released bundles (named by RS-GPT with SLSA); no MAS-RA item names it yet. |

## Codebases

Re-checked on 2026-10-12 under Q-RA1 (40 of 41 repositories found; not found: microsoft/Agensh; re-check output sha256 `86bc87a10b55a3f7826effede3436dc4997ef03d2773af3d83b87393c9d044f4`). The only network use was this one owner-approved build-time pass; validation reads repository files only. Each record is dated GitHub metadata and the default-branch commit at the check; the licence-policy outcome applies the pinned policy's lists to the GitHub-reported identifier. Nothing is qualified, vendored or released.

| Codebase | Reuse mode | Licence (GitHub) | Policy outcome | Licence ceiling | Pinned commit | Items |
|---|---|---|---|---|---|---|
| [google-research/veriharness](https://github.com/google-research/veriharness) | VENDOR_CANDIDATE | Apache-2.0 | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `0f10db9818920f8d79641b23d9311c4877f67702` | MAS-RA-001 |
| [princeton-pli/AggAgent](https://github.com/princeton-pli/AggAgent) | REFERENCE_DESIGN | Apache-2.0 | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `9638f7d88aee01eb636c02841e13a05bb2e3c449` | MAS-RA-001 |
| llm-as-a-verifier | NOT_APPLICABLE | - | NO_REPOSITORY | DESIGN_REFERENCE_ONLY | - | MAS-RA-001 |
| [harbor-framework/harbor](https://github.com/harbor-framework/harbor) | TEST_ORACLE_CANDIDATE | Apache-2.0 | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `dc933be707feafbb9efcdf092cb8a0e391332617` | MAS-RA-002, MAS-RA-010 |
| [SWE-agent/mini-swe-agent](https://github.com/SWE-agent/mini-swe-agent) | REFERENCE_DESIGN | MIT | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `04d809ceab9df28f9adaed044884180159172930` | MAS-RA-002, MAS-RA-007, MAS-RA-008 |
| [Arize-ai/phoenix](https://github.com/Arize-ai/phoenix) | LICENSE_BLOCKED | NOASSERTION | PLANNED_UNRESOLVED | DESIGN_REFERENCE_ONLY | `d0dc9e5ff0a33a1962da6aae83e6f56ac72c444f` | MAS-RA-003 |
| [langfuse/langfuse](https://github.com/langfuse/langfuse) | PLANNED_BASELINE | NOASSERTION | PLANNED_UNRESOLVED | DESIGN_REFERENCE_ONLY | `5c13efd919d333737d56aaa9b2af7c107ee0d38a` | MAS-RA-003 |
| [OpenHands/OpenHands](https://github.com/OpenHands/OpenHands) | REFERENCE_DESIGN | MIT | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `3f5654ac02c2a74661daa224bcfc8962643a58f2` | MAS-RA-003, MAS-RA-008 |
| [microsoft/Agensh](https://github.com/microsoft/Agensh) | NOT_RETRIEVABLE | - | NOT_RETRIEVABLE | DESIGN_REFERENCE_ONLY | - | MAS-RA-004, MAS-RA-009 |
| [yuzhenmao/DeLM](https://github.com/yuzhenmao/DeLM) | LICENSE_BLOCKED | NOASSERTION | PLANNED_UNRESOLVED | DESIGN_REFERENCE_ONLY | `66617616e708758f91624e5cc03659732b82f6a6` | MAS-RA-004, MAS-RA-009 |
| [ybkim95/agent-scaling](https://github.com/ybkim95/agent-scaling) | REFERENCE_DESIGN | MIT | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `072276fd3ae71cf095587f1232e8eefc17a21898` | MAS-RA-004 |
| [anthropics/claudes-c-compiler](https://github.com/anthropics/claudes-c-compiler) | REFERENCE_DESIGN | CC0-1.0 | OPEN_CONTENT | DESIGN_REFERENCE_ONLY | `6f1b99acb2f4ec2414592136c2009fe7713deec3` | MAS-RA-004 |
| [langchain-ai/langgraph](https://github.com/langchain-ai/langgraph) | PLANNED_BASELINE | MIT | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `799c2f04fd3a56186e24e9fb8bbf3568e543cfbe` | MAS-RA-004 |
| [microsoft/agent-framework](https://github.com/microsoft/agent-framework) | REFERENCE_DESIGN | MIT | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `726dcff81e93f02fc18f7ebf0f477d6cbe2186fd` | MAS-RA-004 |
| [crewAIInc/crewAI](https://github.com/crewAIInc/crewAI) | REFERENCE_DESIGN | MIT | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `753d1923660207989b6974ef414b8d91cd85e57c` | MAS-RA-004 |
| [go-gitea/gitea](https://github.com/go-gitea/gitea) | REFERENCE_DESIGN | MIT | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `6384ed4d118005944e287c19dc26cb2fd75930f3` | MAS-RA-004 |
| [mattermost/mattermost](https://github.com/mattermost/mattermost) | LICENSE_BLOCKED | NOASSERTION | PLANNED_UNRESOLVED | DESIGN_REFERENCE_ONLY | `8a378be804d9ff0bf331507dddd494943868c1ed` | MAS-RA-004 |
| [stanford-iris-lab/meta-harness](https://github.com/stanford-iris-lab/meta-harness) | REFERENCE_DESIGN | MIT | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `8123ccabe2b19fa1123090b2e5f1bacc20963ce8` | MAS-RA-005, MAS-RA-006 |
| [china-qijizhifeng/agentic-harness-engineering](https://github.com/china-qijizhifeng/agentic-harness-engineering) | REFERENCE_DESIGN | MIT | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `8b2a55d97590363fe50c3cc6b5e833b020a4bb4c` | MAS-RA-005, MAS-RA-006 |
| [qzzqzzb/Self-Harness](https://github.com/qzzqzzb/Self-Harness) | LICENSE_BLOCKED | none | DENY_MISSING_LICENSE | DESIGN_REFERENCE_ONLY | `2720dbb3f52283684f4b85a1065d642df1779dd8` | MAS-RA-005 |
| [promptfoo/promptfoo](https://github.com/promptfoo/promptfoo) | PLANNED_BASELINE | MIT | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `162c43a4c037b965df9b2f1e4542b96f4f9b8144` | MAS-RA-005, MAS-RA-010 |
| [gepa-ai/gepa](https://github.com/gepa-ai/gepa) | VENDOR_CANDIDATE | MIT | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `462e437a09be67d2acb59564cc0ea59132f5777c` | MAS-RA-006 |
| [stanfordnlp/dspy](https://github.com/stanfordnlp/dspy) | VENDOR_CANDIDATE | MIT | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `f1260ff14610286cb295c7d3a5ee2cbfd0ba5cb9` | MAS-RA-006 |
| [FoundationAgents/AFlow](https://github.com/FoundationAgents/AFlow) | REFERENCE_DESIGN | MIT | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `3f457218fc716093fe53f6df8a5d5e6379d66346` | MAS-RA-006 |
| [ShengranHu/ADAS](https://github.com/ShengranHu/ADAS) | REFERENCE_DESIGN | Apache-2.0 | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `2702bee8fefda42255efc5be9f60e3bd3db96ae4` | MAS-RA-006 |
| [algorithmicsuperintelligence/openevolve](https://github.com/algorithmicsuperintelligence/openevolve) | VENDOR_CANDIDATE | Apache-2.0 | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `30d97520d4cc2db91e537ec4e9134462445ecaa0` | MAS-RA-006 |
| [metaevo-ai/harness-zero](https://github.com/metaevo-ai/harness-zero) | REFERENCE_DESIGN | Apache-2.0 | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `a4a6223241479c750fdab827c3a449bb1d41b99a` | MAS-RA-007 |
| [zzy1127/OPHSD-On-Policy-Harness-Self-Distillation](https://github.com/zzy1127/OPHSD-On-Policy-Harness-Self-Distillation) | LICENSE_BLOCKED | none | DENY_MISSING_LICENSE | DESIGN_REFERENCE_ONLY | `20eaa0c8b0674fbf81aa780a8cf4e0d7c550d4ea` | MAS-RA-007 |
| [krafton-ai/WHALE](https://github.com/krafton-ai/WHALE) | REFERENCE_DESIGN | Apache-2.0 | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `63faf4deb2dd2938775af6e2b020a9030f3aa697` | MAS-RA-007 |
| [jaz-lang/jaz](https://github.com/jaz-lang/jaz) | REFERENCE_DESIGN | Apache-2.0 | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `0803d4971be785e95b80054b02259664d70fa3da` | MAS-RA-008 |
| [alexzhang13/rlm](https://github.com/alexzhang13/rlm) | REFERENCE_DESIGN | MIT | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `d04208afbad29ca675ab13478c40ee8bebc84bfe` | MAS-RA-008 |
| [openai/codex](https://github.com/openai/codex) | REFERENCE_DESIGN | Apache-2.0 | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `97239fd052db455bd08c41afcdab738e0fe83b87` | MAS-RA-008, MAS-RA-004 |
| [huggingface/smolagents](https://github.com/huggingface/smolagents) | REFERENCE_DESIGN | Apache-2.0 | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `96f33faaf028479119ec8d34507b47694cf14e34` | MAS-RA-008 |
| [langchain-ai/deepagents](https://github.com/langchain-ai/deepagents) | REFERENCE_DESIGN | MIT | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `2069079e09546060f5b52b2cd4f0e3c813e820f3` | MAS-RA-008, MAS-RA-009 |
| stripe-minions | NOT_APPLICABLE | - | NO_REPOSITORY | DESIGN_REFERENCE_ONLY | - | MAS-RA-008 |
| [google-research/reasoning-bank](https://github.com/google-research/reasoning-bank) | REFERENCE_DESIGN | Apache-2.0 | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `ed80611788292ea739f1effd31f16c53823b8a0d` | MAS-RA-009 |
| [letta-ai/letta](https://github.com/letta-ai/letta) | PLANNED_BASELINE | Apache-2.0 | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `5bcdd177d70fa2b31a754cfcd801e77b2e1ab16a` | MAS-RA-009 |
| [camel-ai/camel](https://github.com/camel-ai/camel) | REFERENCE_DESIGN | Apache-2.0 | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `e5e55256e9446f744bf7309c478b084587dbf985` | MAS-RA-010 |
| [SWE-agent/SWE-ReX](https://github.com/SWE-agent/SWE-ReX) | REFERENCE_DESIGN | MIT | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `5c995c365dfb1fd5bc56fda688be5d8538f9931f` | MAS-RA-010 |
| e2b | NOT_APPLICABLE | - | NO_REPOSITORY | DESIGN_REFERENCE_ONLY | - | MAS-RA-010 |
| jit-agent-darwinx | NOT_APPLICABLE | - | NO_REPOSITORY | DESIGN_REFERENCE_ONLY | - | MAS-RA-006 |
| [Gloriaameng/Awesome-Agent-Harness](https://github.com/Gloriaameng/Awesome-Agent-Harness) | INDEX_ONLY | CC-BY-4.0 | OPEN_CONTENT | DESIGN_REFERENCE_ONLY | `3be13b047f80cb6c641fd8791f0303cad697b8ee` | MAS-RA-000 |
| [ai-boost/awesome-harness-engineering](https://github.com/ai-boost/awesome-harness-engineering) | INDEX_ONLY | NOASSERTION | PLANNED_UNRESOLVED | DESIGN_REFERENCE_ONLY | `e82dcdecc0e1cac0082b87a590b19d9f96a6b09a` | MAS-RA-000 |
| [YennNing/Awesome-Code-as-Agent-Harness-Papers](https://github.com/YennNing/Awesome-Code-as-Agent-Harness-Papers) | INDEX_ONLY | MIT | DEFAULT_ALLOWED | REUSE_AFTER_GATES | `06b0d447951a08b7dd6b9f88001562b718b4f5a8` | MAS-RA-000 |
| [EvoMap/awesome-agent-evolution](https://github.com/EvoMap/awesome-agent-evolution) | INDEX_ONLY | NOASSERTION | PLANNED_UNRESOLVED | DESIGN_REFERENCE_ONLY | `596c20ba06738d5d7fcb10afd9934e507b4b81bd` | MAS-RA-000 |
| harnessdev | NOT_APPLICABLE | - | NO_REPOSITORY | DESIGN_REFERENCE_ONLY | - | MAS-RA-002, MAS-RA-005 |
| milo-listings | NOT_APPLICABLE | - | NO_REPOSITORY | DESIGN_REFERENCE_ONLY | - | MAS-RA-006 |

## Acceptance IDs for MAS-RA-001..010

Proposed, not published or dispatchable. Items whose only predecessor is MAS-RA-000 become READY when this packet merges.

| Item | Proposed packet | Depends on | Gates | Ready on merge | Acceptance IDs |
|---|---|---|---|---|---|
| MAS-RA-001 | MET-MAS-001 (proposed contract packet) | MAS-RA-000 | - | yes | MAS-RA-001-A1 Verdict and evidence-ledger schema with reference model and rejection vectors; MAS-RA-001-A2 check-kind registry (deterministic, model-based with evidence, disagreement resolver, consensus challenger); MAS-RA-001-A3 independent review record |
| MAS-RA-002 | MET-MAS-002 (proposed contract packet) | MAS-RA-000 | CONF-WG-001 | yes | MAS-RA-002-A1 RunManifest schema and reference model; MAS-RA-002-A2 distribution-gate rule (seeds, repetitions, tolerance) and the reporting tuple; MAS-RA-002-A3 held-out split declaration format |
| MAS-RA-003 | MET-MAS-003 (proposed contract packet) | MAS-RA-000 | - | yes | MAS-RA-003-A1 RunEvent schema and OTel GenAI attribute mapping; MAS-RA-003-A2 MAS metric definitions with formulas and units; MAS-RA-003-A3 MAST annotation vocabulary |
| MAS-RA-004 | MET-MAS-004 (proposed contract packet) | MAS-RA-000, MAS-RA-003 | - | no | MAS-RA-004-A1 TopologySpec and AgentSpec schemas with vectors; MAS-RA-004-A2 Coordinator contract with the two reference modes and claim/lock semantics; MAS-RA-004-A3 topology-selection rule and agent-count budget fields |
| MAS-RA-005 | MET-MAS-005 (proposed governance contract) | MAS-RA-001, MAS-RA-002 | - | no | MAS-RA-005-A1 admission-gate contract with the ordered checks and refusal vectors; MAS-RA-005-A2 candidate lineage record schema (including rejected candidates); MAS-RA-005-A3 promotion and revocation binding to H14 |
| MAS-RA-006 | post-GA successor packets (proposed; R09 and R08), after MAS-RA-005 | MAS-RA-005, MAS-RA-004 | - | no | MAS-RA-006-A1 replay and counterfactual runner over recorded runs; MAS-RA-006-A2 prompt and topology optimizer adapter (MASS/AFlow class) behind the gate; MAS-RA-006-A3 lineage store with Pareto reports |
| MAS-RA-007 | post-GA successor packets (proposed; R06, R08 and R09), after MAS-RA-005 | MAS-RA-005, MAS-RA-002 | - | no | MAS-RA-007-A1 reviewed-trajectory export format (student action, PASS/REPLACE review, evidence); MAS-RA-007-A2 fine-tuning recipe under signed promotion; MAS-RA-007-A3 evaluation of the distilled model against the external harness baseline |
| MAS-RA-008 | MET-MAS-006 (proposed contract packet) | MAS-RA-000 | CONF-A3-001 | yes | MAS-RA-008-A1 loop and hook contract with budget fields and refusal vectors; MAS-RA-008-A2 tool-call and tool-result schemas (capability token, provenance, trust label); MAS-RA-008-A3 bounded-retry and deterministic-gate interleaving rules |
| MAS-RA-009 | MET-MAS-007 (proposed contract packet) | MAS-RA-000, MAS-RA-001 | - | no | MAS-RA-009-A1 board entry schema and admission rule with vectors; MAS-RA-009-A2 context-scope model (private, durable, shared, lineage) and the pass-by-reference rule; MAS-RA-009-A3 compaction threshold and summary record |
| MAS-RA-010 | R12 CONF-MAS-001 (proposed), after MAS-RA-004 and MAS-RA-008 | MAS-RA-004, MAS-RA-008 | - | no | MAS-RA-010-A1 R12 test source for the MAS adversarial classes with a simulation harness; MAS-RA-010-A2 results ledger per class with distribution gates; MAS-RA-010-A3 campaign record consumed by CONF-A3-001 |

## Open items

| Id | Subject | Text | Carried to |
|---|---|---|---|
| OI-1 | jaz-lang/jaz-evals | JAZ's evaluation repository is named in the paper (p.1) but is not among the 41 repositories of the approved Q-RA1 pass, so it was not metadata-checked. | MAS-RA-008 |
| OI-2 | llm-as-a-verifier | The syntheses name a site and a plugin, not a repository; it was not located or licence-checked (outside the approved Q-RA1 pass). | MAS-RA-001 |
| OI-3 | harnessdev | HarnessDev's seed, audit script, held-out splits and pinned candidate set are stated as forthcoming (pp. 22, 24-25); no repository was checked (outside the approved Q-RA1 pass). | MAS-RA-002, MAS-RA-005 |
| OI-4 | microsoft/Agensh | Not found on GitHub on 2026-10-12, at the roadmap check and again at the packet re-check; the paper remains the reference. | MAS-RA-004, MAS-RA-009 |
| OI-5 | licence-blocked upstreams | Self-Harness, OPHSD, DeLM, Mattermost and Phoenix stay design references; whether to open a licence enquiry is an open owner choice, recorded in the roadmap. | MAS-RA-004, MAS-RA-005, MAS-RA-007, MAS-RA-009, MAS-RA-003 |
| OI-6 | Arize-ai/phoenix | GitHub reports NOASSERTION while RS-GPT names the Elastic License 2.0, which the licence policy denies for default distribution; either way it is a design reference only. | MAS-RA-003 |
| OI-7 | VeriHarness rollout dataset | The rollout pool VeriHarness releases as a Hugging Face dataset (p.22) is listed as a fixture source, but no licence is stated in the paper and the dataset was outside the approved Q-RA1 pass; the policy requires a dataset licence approval before any use. | MAS-RA-001, MAS-RA-002 |

## Not claimed

- No public contract, selector, catalog, policy or runtime change; no task packet is published or dispatched for MAS-RA-001..010.
- No upstream is qualified, vendored, released or licence-cleared: the records are dated GitHub metadata and a pinned default-branch commit, not artifact or licence closure evidence.
- Figures from the syntheses and from the secondary corpus are reported research results, not platform evidence.
- The three syntheses and the eight PDFs are referenced by sha256 only; they are not copied here.
- The grounding records are derived data written on 2026-10-12; they are not reproductions of the papers, and authors are not recorded.
