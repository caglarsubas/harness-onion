# Owner decisions for CHAIN-PRODUCT-PUBLISH-001 (MET-PERF-044)

Verbatim as relayed by the lane monitor. `rule.json`'s evidence cites this file by path and sha256.

## Q-SEC3-TWO (owner, 2026-10-30, via AskUserQuestion)

Owner Q-SEC3-TWO, 2026-10-30, via AskUserQuestion. Record verbatim as an owner-decision record and cite it in the identity-rule record's evidence when 273 lands, so IND-BANK-002..005 need no second question.
1. "General form (Recommended)": extend the chain's step vocabulary with a pinned product-packet list. K ≥ 1 product YAMLs sit beside the slot's meta packet, each pinned by digest in the authority, as a general rule from slot 273 on.
2. "Yes, that order (Recommended)": 272 RELEASE-PROFILE-001 when packet-ready (if not ready when 272 opens, the chain item takes 272), 273 CHAIN-PRODUCT-PUBLISH-001, 274 MET-SECTOR-003 re-based onto 273, then the T4 trio.
The visionary's design read is visionary/2026-10-30-sec3-two-answers.md (1405e254). Shape:
- the list form, K ≥ 1;
- vectors for K = 0 (unchanged rule) and K = 2;
- refusals: an unlisted product path, an id colliding with a chain packet, a product packet targeting harness-onion, and any product YAML extending the 64 argv;
- D, G1 and G2 get the product list as the one new parameter, everything else frozen.
The identity-rule change is CONTRACT_AND_SOURCE, not gate. The packet is still the owner's head-bound merge through briefs.json. Don't add the identity rule to the gate record.
Next for R00:
- RELEASE-PROFILE-001's design continues, first in line.
- CHAIN-PRODUCT-PUBLISH-001's design round is paper work beside it: DESIGN rev 1 to me when ready, design questions recommendation first.
- The roadmap item is the visionary's RMW under the lock.

## Q-CPP-2 (owner, 2026-10-30, via AskUserQuestion; recorded in MON-CPP-D2)

- **Q-CPP-2, owner, 2026-10-30, AskUserQuestion: "Yes, one bundle (Recommended)".** The verifier rule widens to:
  - exactly one added packet names this repository, so a product-only PR is refused;
  - every other added packet names a repository listed in architecture/repositories.yaml (R01..R12), is listed in that packet's allowedPaths, and changes nothing else;
  - the verifier runs only that packet's commands and never reads a product packet for commands;
  - "newest accepted packet" means the newest added YAML naming this repository.
  It is folded into the same owner bundle as VERIFIER-EXT-R03, with one review and one root install. 274 waits for that install. Record it verbatim.
