# I05 gate channel v3 — supplementary vectors (AF2-I05-1, plan obligation I05-4)

Alpha 2A; 2026-10-11. Status: **ADOPTED_FOR_SOURCE_PUBLICATION** (published by W03-AMEND).

The I05 v3 contract (`../i05-gate-channel-v3/`, ADOPTED) carries one finding, AF2-I05-1
(`../i05-gate-channel-v3/status.json:58`): no vector shows that a second `STORAGE_FAIL_AFTER` replaces a pending first one
(README:226-229). Later layers pin the v3 vectors (`architecture/enforcement-test-plan/traceability.json`), so they
stay byte-identical; `vectors.json` (`planeon.internal.effect-gate-supplement/v1`: the v3 transcript format plus an
optional `equals`, and the configuration named by reference to the v3 file)
here adds six transcripts in the v3 transcript format, replayed by the pinned v3 model
(`scripts/i05_gate_channel_v3.py`, sha256 `2c7985b539c0ce8eb79eaabfa1f1ab7d43bdca7515defc590a76ecb1697ca959`) with the v3 ACTIVE configuration:

| ID | Intent |
|---|---|
| S01 | I05-4: a second STORAGE_FAIL_AFTER replaces a pending first one (AFTER 0, then AFTER 1): every non-injection output and the final snapshot equal S02's |
| S02 | I05-4 reference: AFTER 1 alone (the CLOSED record succeeds; the INVALIDATED storage-failure path follows the failed DENIED record) |
| S03 | I05-4: the replacement also holds the other way (AFTER 1, then AFTER 0): every non-injection output and the final snapshot equal S04's |
| S04 | I05-4 reference: AFTER 0 alone (the CLOSED record fails) |
| S05 | Injection accumulation (model-defined): after NEXT, NEXT, an AFTER 0 failure is added to the two pending NEXT failures rather than replacing either, so three consecutive record attempts fail |
| S06 | Injection queue order (model-defined): the AFTER failure queues behind the pending NEXT failures. The BIND succeeds; NEXT, NEXT torn and AFTER 0 are then pending; the ARM run fails the first record attempts, and the GENERATION_STATUS after it reads a journalDigest that differs if the AFTER failure were put in front of the queue. The CLOSE on the HELD generation writes no record, so the queued remainder stays pending and fails the RESTARTED record after GATE_RESTART (a pending failure crosses the restart, as in T104) |

S01 and S03 carry `equals`: every output of a non-injection event and the final snapshot equal the named reference; S02
and S04 differ from each other, so the pair shows the replacement in both directions. In all four the injected failure
lands before the restart (AFTER 1 fails the DENIED record, AFTER 0 the CLOSED record), so they do not depend on a pending
injection surviving a restart. S05 shows accumulation: after two pending NEXT failures an AFTER 0 failure is added, not
merged, so three consecutive record attempts fail. S06 pins the queue order, which the README's "the (k+1)-th record
attempted from then on" does not state exactly (model-defined): the AFTER failure queues behind the pending NEXT failures.
Within one failure run the order is not visible (a clean failure leaves no record and the failures fall on consecutive
attempts), but a run uses only a few record attempts, so a queued remainder stays pending for a later record (in S06
the RESTARTED record after the restart), and the `journalDigest` that a GENERATION_STATUS reads in between differs if the
AFTER failure were put first. With
these vectors AF2-I05-1 is closed for the v3 contract (recorded in this directory's status record after review); the v3
bytes do not change.
