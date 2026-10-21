# CHAIN-COMPACTION-001 (harness-onion slot 255): owner and monitor decisions

## 2026-10-19, PA-D9 (D9a) (owner, principles audit; as recorded in roadmap item CHAIN-COMPACTION-001)

After slot 253, a ci/ packet that (1) reports per layer what the chain costs and what it catches, as the ablation evidence,
(2) compacts the chain where the report shows no loss of a required check, and (3) makes the canary accept only the denial
outcomes the trusted-runner contract names.

## 2026-10-21, Q-255 slot assignment (owner via the lane monitor; verbatim as relayed, received 2026-10-21 00:16 +08:00)

> Owner decision (2026-10-21, via the lane monitor), verbatim: "CHAIN-COMPACTION-001 (Recommended)" for harness-onion slot 255. Record it verbatim and dated.
> - Slot 255 is yours: D9a history-chain compaction with a cost report, plus the firejail canary fix aligned with the trusted-runner contract, as the roadmap item says.
> - It's a ci/ packet, so gate material: the owner's transport approval of the exact head plus a per-PR merge, contract-packet oracle tests outside the candidate, and D5a records.
> - Motivation for the plan: verifies of 857, 869 and 956 s, all above the 750 s floor; a dry run of 1,170 s under load; diagnostics at 71% of the caps.
> - The plan should state the target verify time and diagnostics headroom it buys, and must not weaken any inherited acceptance check. Any change to the 64 argv or to a contract file needs an explicit owner question.
> GO for the plan and contract (light), then review rounds.
>
> HE-004-I01's dossier (R10, light) is also GO. Sequence the two within your lane as you see fit; heavy steps still come to me one at a time.

## 2026-10-21, Q-CAN-7, Q-CAN-4 facts and MON-CAN-WALK (monitor; verbatim)

> Monitor, Q-CAN-7. The "four contract files" are MONITOR.md §5's list: ci/verify-offline.sh, ci/warm-source-isolation.sh, ci/network_canary.py and ci/run_packet_argv.py.
> - It's my own cross-check for transport PRs, not something the verifier enforces. verify_pr.py pins no file digests, only the ci/ transport-approval rule with the TRANSPORT_EXEMPT pattern.
> - It matches the transport files the edges carry. If 255 changes network_canary.py on purpose, I check its digest against the reviewed value and update §5's reference after the merge.
>
> Q-CAN-4, item-level facts from the published edge records at 29c84b36:
> - ci/network_canary.py is consumed BYTE_IDENTICAL (1be4a837, mode 100755) by two consumers:
>   - R10: the operator–harness-engineering edge v8, its providerPath/consumerPath entries;
>   - R12: the conformance-labs–harness-engineering edge record.
> - So a fix in 255 leaves two consumer copies stale. Each consumer would need its own forward-fix transport packet to adopt the new file: a ci/ change in R10 and in R12, each with the owner's transport approval.
> - Put this in PLAN.md as an owner question with options:
>   (a) fix in 255, publish successor edge versions for both consumers that record the provider change, and queue R10 and R12 adoption packets;
>   (b) split the canary fix out of 255 into its own packet, sequenced with the two adoptions, so 255 stays compaction-only;
>   (c) other.
>   My leaning is (b): it keeps the PERF packet narrow and the gate-material diff small. Your recommendation should rest on your own analysis.
>
> Disclosures: accepted as benign (MON-CAN-WALK).
> - The grep printed names only, from nested edge copies, and they were excluded afterwards.
> - The legacy term appeared only in a scratch copy of a published byte, deleted at once.
> - A few unwrapped trivial pipes and builtins.
> Keep the exclusion pathspecs from the first command next time.

## 2026-10-21, the safety event, Q-CC-CAP and PLAN §9 (owner via the lane monitor; verbatim as relayed)

> Monitor: owner decisions on CHAIN-COMPACTION-001 (2026-10-21, via the lane monitor). Record them verbatim and dated:
>
> 1. Safety event (r5 classifier withhold): "Keep static-only + cap (Recommended)".
>    - All bypass-form analysis stays static only: paper and ast.parse. No bypass, interposition or forwarding code is written or run anywhere, including in WORK.
>    - Q-CC-CAP is ACCEPTED: the head-allow-list class is final.
>    - Revision 7 (8fd26afd) closes round 6, text-only. Don't run round 7 for that class. Any MAJOR or new class would still need a full round.
> 2. PLAN §9: "Accept all (Recommended)". That is Q-CC-1 (b), 2 (a), 3 (b), IDENTITY (a), RESIDUAL (a), 4 (a), 5 (b), 6 (a), 7 (c), 8 (a), C4 (a), SPLIT (b) canary as its own packet, GATE (a) owner per-PR merge, TARGET (a); the canary Q-CAN-1..3, 5 and 6 (a).
>
> M1 GO comes after the parallel lane's R12 PR verify, which is about to start and takes about 8 min. I'll send the word when it posts. It's then the only heavy job: 8 GiB cap, out-of-tree, DATA_CHECK_ONLY.
>
> HE-004-I01a: the design is complete (rev 6, 2d976d19). Its reviewer slips are accepted as benign (MON-I01A-SLIPS). I'm putting Q-I01A-1..9 to the owner now.

## 2026-10-21, MON-M1-ACCEPT (monitor) and "Finish 255; new item" (owner via the lane monitor; verbatim as relayed)

> Monitor:
> - MON-M1-ACCEPT: M1's rc=1 is accepted as measurement artifacts. The repository's profiling layer fail-closes correctly under the ambient sys.monitoring tool. All other passes are rc 0, the end checks are clean, and the measurements are usable with the 26 profiler-sensitive tests left out.
> - Owner decision (2026-10-21, via the lane monitor), verbatim: "Finish 255; new item (Recommended)". Record it verbatim and dated. It means:
>   - complete 255 as planned (C1+C2) with the measured numbers;
>   - the visionary adds a separate PERF item for argv 1-62's authority re-reading. Its design must come back to the owner, because it touches the freshness rule Q-PERF40-2 (a).
> - GO for PLAN revision 8:
>   - the M1 numbers;
>   - the payload-rule outcome (both explicit blocks fail, so only the parametrize and loop edits remain);
>   - the B1 landing about 0.88, stated plainly with the decision rule;
>   - the fact map.
>   Then a short delta contract review, static-only rule unchanged. If B1 lands in the owner band at M2, it comes to the owner.
> Send me the item-level facts of the authority-read finding (the counts above are enough) and I'll pass them to the visionary.

## 2026-10-21, Q-CC-B4 (owner via the lane monitor; verbatim as relayed) and MON-CC-R7-SLIPS (monitor)

> Monitor: owner decision Q-CC-B4 (2026-10-21, via the lane monitor), verbatim: "(a) Relax B4 to ≤ 0.65 (Recommended)". Record it verbatim and dated.
> - B4's bar is now ≤ 0.65, with its definition and failure line kept as restored in rev 9.
> - B1's rule is unchanged: 0.88-0.91 at M2 goes to the owner; above 0.91 the packet stops.
> GO for the last short delta review on this point only (static-only rule unchanged), then report. The build waits for my word after it.
>
> r7's slips (unwrapped builtins, a stray echo zsh rejected, time ahead of timeout) are accepted as benign: MON-CC-R7-SLIPS.
>
> FYI: CHAIN-COMPACTION-001 on the roadmap still carries the external blocker "I06-RBAC-V4 at slot 254 merges first". That was resolved by 29c84b36 (#208). Clear it in your next roadmap RMW for this item, at the latest the merge RMW.

## 2026-10-21, "Build now" (owner via the lane monitor; verbatim as relayed) and the BUILD GO (monitor)

> Monitor: owner decision (2026-10-21, via the lane monitor), verbatim: "Build now (Recommended)". The owner saw the restated B4 projection (about 0.55-0.66, central about 0.6) and B1 at the 0.88 line. Record it verbatim and dated.
> - Round 8 (ce1f4823) closes with rev 11 (a9086656), wording only. No further review round.
> - BUILD GO for CHAIN-COMPACTION-001, light: a new harness-onion worktree on main 29c84b36. Write C1 and C2 under rev 11, the identity-rule and strict-bridge artefacts, and the fact map. Static-only rule as before. Register the worktree name with me.
> - M2 (heavy, the measured A/B), the pre-check, dry run and push each wait for my word.
> - If M2 lands B1 in 0.88-0.91 or B4 above 0.65, stop and send me the numbers for the owner.
> I01a's light build continues; its heavy steps also come to me one at a time.

## 2026-10-21, Q-CC-F1, Q-CC-F2 and F3 (owner via the lane monitor; verbatim as relayed) and the build resume

> Monitor: these are the owner's answers on 255, verbatim from the owner's picks, plus the push word for I01a.
>
> **255 owner answers:**
> - Q-CC-F1: "Edit the 241 test (Recommended)". This is option (a): one inherited edit, to the 241 test only, asserting live NEVER_SHARED == 241's set | the 255 identity test names. It is a canonical reverse hunk under Q-CC-6 (a).
> - Q-CC-F2: "Two exact classes (Recommended)". This is option (a): {192} and {193..head-1}, with exact AST comparison that keeps docstrings.
> - F3: "Accept (Recommended)". The checker goes in scripts/chain_identity.py, its bytes are pinned to the 255 era by the live test, and it is loaded through 254's existing era-loader shape. The head avoids 254's two module-level forms that are not open to a new head.
> Record them as owner decisions in the plan or build notes. The agent may resume at U3, light only. M2 is heavy and runs only on my word. The build-agent disclosures (untimed builtins, two steps over 60 s, enforcement-named files in the scratch export deleted unread) are accepted as NOTEs.

## 2026-10-21, GO for M2 on ed000a8b (monitor; verbatim as relayed)

> Monitor: GO for M2 on ed000a8bf4822702890f0fad2e5afc510017247f.
> I cross-checked: tree 473abdc8, one commit on 29c84b36 (still harness-onion main), worktree clean, 0 ci/ paths, planeon identity. The base tree is harness-onion-i06v4 at c324d86a.
> - **It is the one heavy job.** No verify is pending and R10/R12 have no open PRs. The parallel lane stays light (contract r4, ≤6 short test runs).
> - **Host load is about 15 from the owner's own work** (the VM, an orchestrator run, a llama-server). By the owner's no-load-wait rule, start anyway. The interleaved base/head design covers it. In the report, give each run's 1/5-min load and the spread (min/max or CV) of each tree's full-run times beside B1-B5. If noise alone could move B1 across the 0.88/0.91 lines, say so; that case goes to the owner with the numbers, like the band rule.
> - **The kill-and-rerun rule on PAUSE, HOLD_BY_VERIFY, holdCargo or a verify stands**, with the 8 GiB cap and the 90-min budget. Over budget: stop and report.
> - **Order:** M2 now and M3 after is accepted; it uses the free heavy slot and surfaces the B1/B4 owner gates early. Write the M3 harness light, static-only for every evasion form, and run it on my word. If M3 or a review changes C1, C2, the conftest or the layer's runtime code, tell me, and I'll decide whether M2 re-runs.
> - **The 20 `safe_yaml_load` files:** hold that lever. Raise it only if B1 lands in the owner band; then it goes to the owner as an option.
> The build disclosures are accepted as NOTEs. The terminal-only path print is fine because no file contains it.

## 2026-10-21, MON-M2-CONTROLS (monitor; verbatim as relayed)

> Monitor: accepted, as MON-M2-CONTROLS.
> - The false start measured nothing.
> - The 6 controls are the costliest unchanged, non-chain-layer test files by M1 CPU. They are within the plan's "6 unchanged non-layer files" and are recorded as your choice.
> - The added report fields and the straddle-to-owner rule are good.
> - Launch the M3 harness agent after M2 ends, as you propose. M3 runs on my word.

## 2026-10-21, MON-M2-STOP-LOAD (monitor; verbatim as relayed)

> Monitor: stopping M2 was right, accepted as MON-M2-STOP-LOAD. A deadline-cut run is not a measurement, and the 900 s deadline stays closed.
> - I confirmed the load. It is the owner's own work: a 6-worker regression from a Codex session on another project, an orchestrator run, and the Docker VM. The load is 27/57/55 on 18 cores.
> - (c) is GO now: launch the M3 harness agent, light, static, no runs.
> - For the M2 re-run, (a) with your incomplete-run guard is my recommendation. I'm asking the owner now about timing and the VM, and will relay the answer. Don't start M2 until I give the word.

## 2026-10-21, M2-PARTIAL (owner via the lane monitor; verbatim as relayed)

> Monitor: the owner answered the M2 re-run question. Record it verbatim: "Partial measurement now". That is option (b): run under the current load and compute B1 only over files that completed in all four runs, flagged partial.
> **GO for M2 now on ed000a8b, as M2-PARTIAL:**
> - Turn the new stop-on-incomplete guard OFF for this run, because partial runs are expected. Keep every full run, and record each run's incomplete node and file set: the worker, the deadline hit, and the count.
> - B1 is computed over the intersection of files complete in all four full runs. Report its coverage: the file count and the share of base M1 CPU it covers.
> - B3 and B4 are each flagged complete or partial, with what is missing.
> - The serial sample (80 runs) is unaffected by the deadline; run and report it as planned.
> - Mark the whole report "PARTIAL (owner M2-PARTIAL, load 27-90)", with per-run load and spread as before.
> - The band rules stand: B1 in 0.88-0.91, B4 > 0.65, or a noise straddle goes to the owner. If coverage is too thin to decide B1 or B4 at all, say so; that also goes to the owner.
> - Budget: 120 min for this run (instead of 90), and the 8 GiB cap. Over budget: stop and report.
> - Kill-and-rerun still applies on PAUSE, HOLD_BY_VERIFY, holdCargo or a verify. No verify is expected; no PR is pending.
> - The M3 agent may continue light and static. The parallel lane runs only light review steps (≤6 short test runs).

## 2026-10-21, MON-255-TESTSTRING-FIX (monitor; verbatim as relayed)

> Monitor: good find. The plan after M2 is OK, as MON-255-TESTSTRING-FIX.
> - Before resetting, keep ed000a8b reachable under a local ref (for example `git branch m2/ed000a8b ed000a8b`, never pushed), so the measured head stays inspectable. Then reset the lane's local branch to 29c84b36, re-run mech255.zsh, and send me the new head and tree.
> - Light checks: the static CHECK_TESTS check, and a diff against ed000a8b. It must show only the message string plus the digest pins of that test file in the authority and records. Anything more, tell me before going on.
> - The targeted run of that one test node is GO once M2 has ended. It is light.
> - M2 does not need to re-run for this fix, because C1, C2, the conftest and the layer's runtime code are unchanged. State in the M2 report that the head was measured as ed000a8b, and give the fix's diff summary.
> - M3's run comes later, on my word, against the fixed head.

## 2026-10-21, MON-255-DECISIONS-KEEP (monitor; verbatim as relayed)

> Monitor: M2 report received. The M3 agent's static generators during the serial phase are accepted as a NOTE.
> - **decisions.md: (a) KEEP** the five verbatim sections (MON-255-DECISIONS-KEEP). Commit the fix now and send me the head and tree. The extra +49 lines are a verbatim record copy, which is fine.
> - The B1 straddle, B4 = 0.661 and the two M3 transforms go to the owner now. I'll relay the answers. Run nothing until then: no M3 and no lever.

## 2026-10-21, 255 B1/B4 "Accept and continue", M3 scope "Run 352, rest out of scope" (owner via the lane monitor; verbatim as relayed) and the M3 GO

> Monitor: the owner answered both questions. Record these verbatim:
> - 255 B1/B4: "Accept and continue (Recommended)". B1 = 0.819 (the mean; per-run ratios 0.71-0.94 straddle the lines) and B4 = 0.661 are recorded as owner-accepted. Continue to M3, the packet review, pre-check, dry run and push.
> - M3 scope: "Run 352, rest out of scope (Recommended)". Only the 352 cases under the four approved transforms run. The 207 cases that need "insert an early return" or "retarget to `_checked_own_authority_raw`" are recorded as out of scope, so the static-only rule stays intact. Do not build or keep those two transforms.
> - The `safe_yaml_load` lever is not taken; record it as a possible later PERF item, with your measured 268.6 cpu-s (10.4%) correction.
> **GO for M3 (352 cases) on the fixed head, once it is committed.**
> - When you commit, send me the head and tree. The diff against ed000a8b must be as you described: the match string, the digest pins and the decisions.md sections.
> - M3 is the one heavy job: 6 in parallel, PAUSE/HOLD prefix, capped wrapper, kill-and-rerun on PAUSE, HOLD_BY_VERIFY or holdCargo.
> - The parallel lane is doing one light test step meanwhile.

## 2026-10-21, MON-M3-COLLECT-KILL and the GO for U6 and the packet review (monitor; verbatim as relayed)

> Monitor: M3 is accepted. Part (i) has 0 FAIL and 0 base misses, the benign cases PASS, and part (ii) PASS.
> - **Ruling MON-M3-COLLECT-KILL:** the 6 R10 MAX_FILE_BYTES→0 cases (196, 210, 223, 234, 246, 253) are recorded as "killed at collection in both suites, identical refusal". That makes part (i) PASS. Do not re-run them at near-limit values. In seeded-faults.json, list each case with:
>   - the refusal message ("bounded regular source file" ValueError);
>   - rc 4 in both trees;
>   - zero node reports in both trees;
>   - a note that the harness's raw label was INVALID.
>   The packet review must see this ruling and the raw label.
> - **GO for U6 (records unit), light:** ab.json from M2 (owner-accepted B1 0.819 and B4 0.661, the straddle stated, the head measured as ed000a8b with the fix diff summary), seeded-faults.json from M3 (352 run, 207 out of scope by owner, and the 6 collection kills). Add the integrity checks with their failing mutants, the README and decisions.md refresh, the rebuild with mech255, and the light checks.
> - **Then GO for the independent packet review** on the new head, once the light checks pass. Use a fresh agent and a pinned brief with the PAUSE/HOLD prefix inline. No network. Static-only for every evasion form, with no bypass or interposition code. Record the reviewer identity and the brief sha256 (D5a). Send me the head, tree and brief digest when it launches.
> - Pre-check, dry run and push each need my word.
> M2 stands: U6 adds records and checks only.

## 2026-10-21, packet review r1: GO delta r2, MON-255-P1-4-NOTE, and the pre-check GO (monitor; verbatim as relayed)

> Monitor, on 255 packet review r1:
> - **(a) GO for delta r2 on db65d3652b6e736801e5d87988cdc4a9ff5a260d** (tree 4f444609). Scope: the four-file diff against 659b9b40, the closure of P1-1..P1-3, and a confirmation that C1, C2, the conftest and the layer's runtime code are byte-identical to 659b9b40. Use a fresh agent, the pinned brief with the prefix inline, no network, static-only, and D5a identity with the brief sha256.
> - **(b) P1-4 is carried as a NOTE** (MON-255-P1-4-NOTE). C1's exclusion is narrower than PLAN §4: it does not follow `_serve_tree` or `_readiness_errors`, nor patches of parser state, which affects 8 tests. 255 is gate material (Q-CC-GATE (a)), so I will disclose this in the owner's per-PR merge question. Make sure the packet's records or README name the 8 tests and the exact-bytes argument, so the owner can see it.
> - The reviewer's slip (a name-only `git diff --name-status` without pathspecs) is accepted as a NOTE.
> - **Pre-check:** GO as soon as r2 returns PASS. It is the one heavy job, run under the usual prefix and capped wrapper. Report its result, the head and the timings. The dry run and push each need my word.
