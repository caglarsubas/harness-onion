# Harness-Onion packet review: generic brief (PACKET kind)

Review one harness-onion packet head. You are not its author.

**The rules file.** The launch message names a local round rules file, which both records pin by `rulesSha256`. It
gives:
- the packet id and slot, and your series and round;
- the subject commit and tree, and the base;
- the packet's own decisions and design records;
- the operator rules;
- where to write your record.

Its paths are local and stay out of this published brief. This brief is the same for every packet. What is particular
to one packet lives in its rules file, its design records and its contract directory.

## The subject

- **The packet head:** `{"repository": "harness-onion", "commit": "<40 hex>", "tree": "<40 hex>"}`, against its base,
  harness-onion main at the commit the rules file names.
- **The packet's YAML:** `task-packets/<packet>.yaml`, holding its contracts, exclusions, allowed paths, acceptance
  commands and evidence.
- **The contract files the packet adds or changes,** and their adopted status as the rules file names it.
- **The history-chain mechanics:** the new head layer, its authority and test, the bridged layer, the composed layers
  and their tests, and the catalogs and docs the chain updates.
- **The evolution-surface record** at the base, `architecture/evolution-surface/evolution-surface.json`, with its model.

## Check (at least)

1. **Scope.**
   - Every changed path is among the YAML's allowed paths.
   - Every allowed path that changed is named in the authority's changed files.
   - No excluded change is present.
2. **Gate material.**
   - Derive the gate list from the evolution-surface record at the base, and match it against the diff, exactly and
     case-folded.
   - State every gate path that changed.
   - If any did, the packet needs the owner's per-PR approval of this exact head, and the rules file must name that
     approval as pending.
   - `check_coverage` over the head tree shows 0 unclassified and 0 ambiguous.
3. **The contract bytes.**
   - Every adopted contract file in the diff is byte-identical to the adopted bytes the rules file names.
   - Every change to an earlier contract file is one the YAML's contracts allow.
4. **The chain.**
   - The step rule and the identity rule hold.
   - Every non-head layer change is explained by the bump vocabulary, and the old head by the bridge vocabulary.
   - The new head's checks each have a test that makes them fail.
   - The acceptance commands are inherited unchanged, and no command is added.
5. **The review-record v2 duties.**
   - Every `review-round*.json` in the head tree is frozen or a v2 round with its identity.
   - Every changed `tests/**/test_*oracle*.py` is bound by an oracle identity whose digest matches at the head.
   - `check_tree` holds.
   - Any registry change is exactly what the packet's decisions allow.
6. **Faithfulness.**
   - The README and docs state no claim that the contract or its checks do not hold.
   - The YAML's contracts match the decisions the rules file names.
7. **Privacy and supply chain.**
   - No local path, personal data or credential in any changed file, whole or split into parts.
   - No new dependency.
   - No network use.
   - Nothing that interposes on, forwards, proxies, swaps or bypasses anything.
8. **The pre-check evidence the rules file names,** if any: does it match the head?

## Severities and verdict

- `MAJOR`: wrong or unsafe. For example:
  - a change outside the allowed paths;
  - an unstated gate path;
  - contract bytes that differ from the adopted ones;
  - a chain rule broken;
  - an unbound oracle file;
  - a claim the checks do not hold.
- `MINOR`: a fixable inaccuracy or gap.
- `NOTE`: advice.

**The verdict** is one of these, judged on the exact head:
- `PASS_FOR_PUSH` when no MAJOR or MINOR finding remains;
- `PASS_FOR_PRECHECK` when only the pre-check evidence is outstanding (a pre-check clearance is not merge authority);
- `CHANGES_REQUIRED` otherwise.

Verify every finding against the files; do not guess.

## Record

Write one `planeon.review-record/v2` record at the path the rules file names, with no absolute path in it. It holds:
- kind `PACKET`;
- the series and round the rules file gives;
- the subject (and `base` for a delta round);
- the review date;
- `briefSha256` (this file's sha256), `rulesSha256` and `wrapperSha256`;
- `reviewer` {model, role};
- `verdict`;
- `findings` [{id, severity, location, finding, requiredChange, blocks}];
- `checked`: one line per check above, 1 to 8;
- `notChecked`;
- `disclosures`: your own account of every slip or deviation, or empty when there is none.

The operator writes the identity record beside it. PACKET records stay outside the reviewed tree.
