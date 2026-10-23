# The Linux probe kit

The Linux probe kit is LINUX-PROBE-KIT-001. It is operator-side harness-onion code: the CAMPAIGN_PROXY probe server, its
admission module, the UID ledger and cleanup, the native record inspector, the fixed worker entry, the ten case recipes
and the unsigned receipt candidates.

The kit's scope is set by the probe-kit scope amendment, MET-LIVE-002
(`architecture/probe-kit-scope/amendment.json` and its README). That amendment moves these items out of R12's
CONF-LIVE-003/004/005. R12 keeps:
- the campaign client;
- the narrowed packaging and handoff;
- receipt verification;
- evidence verification.

The Kubernetes API proxy leg (KAP) stays deferred and unowned.

The kit is built in stages:
- **LINUX-PROBE-KIT-ADMISSION (LPK-1):** profile v2 and the admission successor.
- **LINUX-PROBE-KIT-001 (LPK-2):** the kit itself.

The kit reads only the neutral interface contract, never R12's tests.

The installed identities stay as they were: paths, roles, the worker entry name and the signing duties. The kit owns the
module named by `workerEntry`. No new key or signature role is added.
