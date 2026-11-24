# Regulatory alignment (REG-ALIGN-001, MET-014)

`architecture/regulatory-alignment.json` maps two supervisory texts' practices, and the EU AI Act's dated obligations,
to the harness modules and evidence columns that could carry them, with each row's state (MAPPED, PARTIAL or GAP), its
gap kind and its carrier check. It is a published data record: id REG-ALIGN-001, schemaVersion 1.0.0, status PUBLISHED.

What it is not: its `nonClaims` say it, and they bind every reader. Nothing in it says the platform or a tenant
complies with any regulator text. The regulator texts enter by reference only, through `sources` (each by id, title,
nature and, where held, digest).

- Sections: `basis`, `nonClaims`, `sources`, `enums`, `rows`, `euDates`, `rules` and `gapKindMeaning`, as drafted.
- Checker: `scripts/validate_regulatory_alignment.py` (RA_SHAPE, RA_ENUMS, RA_RULES, RA_IDS, RA_SOURCES), standard
  library only; test: `tests/test_regulatory_alignment.py`. The record's eight `rules` are each checked as stated; the
  draft date that rule 7 compares against is this README's provenance `draftDate`.

## Provenance

The record was drafted by R03 and reviewed at intake (R2 PASS); at publication (CONTRACT_296 r2, Q-C296-2 (a)) the
draft-only keys moved here, verbatim:

```json
{
  "draftedBy": "R03 (C25 reading: lane drafts the rows; R00 owns the validator, vectors, oracle and publication)",
  "draftDate": "2026-11-22",
  "intendedPath": "architecture/regulatory-alignment.json",
  "revision": 4,
  "revisionNotes": [
    {
      "revision": 4,
      "note": "Build-R00-Next intake round 1 (ab4c7d00): F1 each obligation locator gives its own page per place (50(5) pdfPage 83; Art 6(1) and 6(2) pdfPage 53); N3 revision notes split, newest first."
    },
    {
      "revision": 3,
      "note": "The EU AI Act as enacted (Regulation (EU) 2024/1689, OJ L 12.7.2024, held bba63044; the visionary's read EUAIA-READ-1 4952ac74): every EU row carries dateAsEnacted (held, Art 113) and dateAsAmended (UNCONFIRMED, secondary note only); the disclosure row is split into 50(1)+50(5) and 50(2); TENANT_OBLIGATION is defined as who implements, not who bears the legal duty."
    },
    {
      "revision": 2,
      "note": "The roadmap visionary's read (DESIGN-BATCH-READ-2 ed606d55, section 5): F-RA-1 no row is MAPPED before its carrier is confirmed (candidateState keeps the draft's view); F-RA-2 dated rows without a held source carry confirmation UNCONFIRMED; F-RA-3 every PRODUCT_GAP names its carrying roadmap items or says none exists."
    },
    {
      "revision": 1,
      "note": "First draft of the rows (ORC-DISPATCH-R03-2)."
    }
  ]
}
```
