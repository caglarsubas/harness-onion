# The neutral Linux probe interface (MET-LIVE-003)

This packet is MET-LIVE-003, slot 262, after 260 (LPK-0) and 261 (the gate packet), work item LINUX-PROBE-INTERFACE, and
it is data only.

It brings the neutral interface contract into harness-onion, byte-identical:
- owner decision Q-PK-6, "Neutral contract (Recommended)", set it up;
- a neutral extractor built it from R12, and three independent review rounds reviewed it;
- the probe kit, LINUX-PROBE-KIT-001, takes its interface form from here;
- R12 vendors `v1/` back, byte-identical.

The record is `binding.json`, its vectors are `vectors.json`, and the reference model is
`scripts/linux_probe_interface.py`.

## The contract files (`v1/`), by sha256

| File | sha256 |
|---|---|
| `architecture/linux-probe-interface/v1/MANIFEST.json` | `67cedd0cc251c61bfd42bc0f100d90923d3bafebb8b38c4e2ae7da891973a9a8` |
| `architecture/linux-probe-interface/v1/README.md` | `049773616005f017bda9a79f22448fc16258ea61d5351ea108a5050213819da3` |
| `architecture/linux-probe-interface/v1/probe-interface.json` | `8c630b41bed90cd10781edc66ba122d2c4caf06fbf5adfaa2be996e3d90233be` |
| `architecture/linux-probe-interface/v1/probe-interface.schema.json` | `2ae672a9912061810f00436e4939c0d4a45074e345b01e3fb04387fed8a5ab69` |

`v1/README.md` names the R12 sources of each field and gap. Those citations are for the contract's reviewers; the kit
takes the form from `v1/probe-interface.json` and its schema, never from R12.

## Source and review chain

**The source:** `mas-harness-conformance-labs` at commit `c17bcfe32df26eab13844b73f65666bb0fa4e0a0`, tree `9c2b2b8a9b064ef6cbffec495a903a4e6ef7afb3`, read at
`e1b8bb8d3306311c0cc854419629e1a380022841`.

**The reviews,** as `v1/MANIFEST.json` records them:

| Round | Review record sha256 | Verdict |
|---|---|---|
| 1 | `bd8e0c971e4618caa0059e59b18f11e066170e1134e2de1f5cd0680ab30717f3` | CHANGES_REQUIRED |
| 2 | `2c128af7f99a2eaf2155c0bf357e2cc22ea94cf3dabad06ac8d347dc4c91223b` | CHANGES_REQUIRED |
| 3 | `08249383067044054693640db5760029d0a9342497ef2201914e5948f4f8fb05` | PASS_FOR_HANDOFF |

## The placeholder binding

The probe-kit scope amendment (MET-LIVE-002, `architecture/probe-kit-scope/amendment.json`, sha256
`3de2d73e0413388ba286899cdd364c876dfbd869510c88537da8b1c91726ef8b`) names the placeholder `NEUTRAL_INTERFACE_CONTRACT` in its predecessor table.
This record binds that placeholder to MET-LIVE-003 and to `v1/probe-interface.json` (sha256
`8c630b41bed90cd10781edc66ba122d2c4caf06fbf5adfaa2be996e3d90233be`).

So the amendment's `R12_SUCCESSOR` and `LINUX-PROBE-KIT-001` wait on this packet.

## Non-claims

The record states exactly these four, and the model pins each text:

- **FORM_ONLY:** This draft records the interface form only; it does not state or imply that any probe output will be accepted by R12.
- **NOT_ACCEPTANCE:** A probe kit built from this contract alone shows the interface form, not acceptance.
- **R12_FILES_AUTHORITATIVE_UNTIL_VENDORED:** R12 vendors this contract back later; until then R12's own files remain authoritative.
- **R12_KEEPS_STATUS_AND_COUNT_RULES:** R12's acceptance rules, the status and count thresholds, stay in R12 (owner, "Keep them in R12 (Recommended)"); the kit's author never learns them.

FORM_ONLY and R12_FILES_AUTHORITATIVE_UNTIL_VENDORED are `v1/MANIFEST.json`'s own `nonClaims`, verbatim; the model also
checks the MANIFEST still holds them. NOT_ACCEPTANCE follows the MANIFEST's `ownerNotes`. R12_KEEPS_STATUS_AND_COUNT_RULES
is the owner's decision.

## Owner decisions

The record quotes exactly these two, and the model pins both rows:
- Q-PK-6: "Neutral contract (Recommended)";
- R12-ACCEPTANCE-RULES: "Keep them in R12 (Recommended)".

The contract build checks each one occurs exactly once in its dated section of the lane's decision record.

## What the model checks

`check(record, read)` returns the sorted refusal texts, `[]` when the record holds. It checks:
- **The shape:** the closed shape, with strict types. `slot` must be an integer, so 262.0 refuses, and a member of the
  wrong type refuses with the shape text. So does input the reader cannot hold, such as a nesting too deep to read.
- **The digests:** each `v1/` file's sha256 equals the record. The record's four digests equal the monitor-verified
  handoff digests, which the model pins.
- **The MANIFEST:**
  - its `files` equal the record's rows for the other three `v1/` files (the MANIFEST cannot hold its own digest);
  - its `source` has exactly the four members `repository`, `commit`, `tree` and `readAt`, and they equal the record's;
  - its review chain equals the record's, and its verdict is `PASS_FOR_HANDOFF`;
  - its `nonClaims` are exactly the two texts above.
- **Schema conformance:** `v1/probe-interface.json` conforms to `v1/probe-interface.schema.json`.
  - The schema must name draft 2020-12 in `$schema`, and may use only these keywords: `$defs`, local `$ref`, `$schema`,
    `title`, `type`, `properties`, `required`, `additionalProperties`, `items`, `prefixItems`, `minItems`, `maxItems`,
    `uniqueItems`, `const`, `enum`, `pattern`, `minLength`, `minimum`, `allOf`, `if` and `then`. Anything else refuses
    with the keyword text, as does a `$schema` naming another draft. A `$ref` that is not local refuses with the
    conformance text.
  - The validator is standard library and keeps draft 2020-12's meaning:
    - a boolean subschema is true or false;
    - an integer-valued number such as 10.0 is an integer, and numbers compare by value in `const` and `enum`;
    - a pattern's final `$` matches only at the very end of the string, as in ECMA-262. Python's `re`, which the
      `jsonschema` library uses, also matches before a final line feed. This is the one place the vectors record that
      the validator and `jsonschema` differ.
- **The placeholder binding:** the record path and its digest, the placeholder present in that record, and the
  interface digest.
- **The owner decisions and the non-claims:** exactly the rows above.

**The vectors:** `vectors.json` holds one positive, 28 negatives each with its full sorted list of refusal texts, and 15
`validatorVectors` that test the validator directly. Every validator vector's expectation agrees with `jsonschema`,
except the one marked `jsonschemaDiffers`.

**The replay** needs no repository read:
`python3 -I -B replay.py <folder holding linux_probe_interface.py, binding.json, vectors.json and v1/> <LPK-0 amendment.json>`

## Reader duties

- **The kit** takes the form from `v1/`, and reads neither R12 nor the extraction's working files.
- **R12** vendors `v1/` back, byte-identical, and keeps its acceptance rules.
- **A later revision** of the interface is a new `v2/` with its own packet.

Adoption is recorded in status.json, not here.

The review history is published in this directory as `review-history-<kind>-r<n>.json`, with its briefs as
`review-history-<kind>-r<n>-brief.md`. These are redacted records from before review-record v2. They are not
`review-round*.json` records and carry no merge authority. This packet's merge authority is its own v2
`MET-LIVE-003/packet` series.
