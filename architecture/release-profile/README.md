# Release profile: profile.banking-readonly-amd64 (RELEASE-PROFILE-001)

`architecture/release-profile.json` (`planeon.internal.release-profile/v1`) records the first release profile: the
overlay-effective closure of `profile.banking-readonly-amd64` (41 nodes: 30 module rows and 11 tenant facts), each
module's deployables, owner, implementation packet or tenant attestation reference, readiness obligation and exit
evidence kinds, the provider set, the exclusions and the non-claims. `scripts/release_profile.py` checks it (refusal
codes RP_SHAPE, RP_CLOSURE, RP_OWNER_PACKET, RP_EXIT, RP_PROVIDER_SET, RP_EXCLUSION, RP_CATALOG_BYTES, RP_TENANT_FACTS,
RP_PACK_BINDING, RP_REGISTRY).

In plain words:

- the pack row of `profile.banking-readonly-amd64` is the white-goods pack (`IND-WG-005`) in this first record, and the
  banking pack is not in the release set; the banking pack enters the release set when, after CHAIN-PRODUCT-PUBLISH-001 (273), one MET-SECTOR packet publishes IND-BANK-005 and, in the same slot, carries the reviewed sector_catalog/overlay-schema revision and the record's new version, so sector_catalog.check never sees the publication and the revision apart (the visionary's Q-RPD1-2 erratum, 2026-10-30);
- the record is bound to one overlay era and is never edited in place: its new version,
  `architecture/release-profile-v2.json`, is issued beside it in that same MET-SECTOR packet;
- it names obligations and evidence kinds only; RELEASE-EVIDENCE-001 holds every state, and the tenant facts'
  digest and signature statuses are the catalog's MISSING_PLANNED marks as projected, not evidence states;
- the Kubernetes provider is a tenant platform row whose attestation is the tenant fact `external.kubernetes-api`.
