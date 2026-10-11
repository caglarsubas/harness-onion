# I05 gate channel v3 — supplementary vectors (AF2-I05-1, plan obligation I05-4)

Alpha 2A; 2026-10-11. Status: **CONTRACT_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW** (published by W03-AMEND).

The I05 v3 contract (`../i05-gate-channel-v3/`, ADOPTED) carries one finding, AF2-I05-1
(`../i05-gate-channel-v3/status.json:58`): no vector shows that a second `STORAGE_FAIL_AFTER` replaces a pending first one
(README:226-229). Later layers pin the v3 vectors (`traceability.json`), so they stay byte-identical; `vectors.json`
here adds five transcripts in the v3 transcript format, replayed by the pinned v3 model
(`scripts/i05_gate_channel_v3.py`, sha256 `2c7985b539c0ce8eb79eaabfa1f1ab7d43bdca7515defc590a76ecb1697ca959`) with the v3 ACTIVE configuration:

| ID | Intent |
|---|---|
| S01 | I05-4: a second STORAGE_FAIL_AFTER replaces a pending first one (AFTER 0, then AFTER 2): every non-injection output and the final snapshot equal S02's |
| S02 | I05-4 reference: AFTER 2 alone |
| S03 | I05-4: the replacement also holds the other way (AFTER 2, then AFTER 0): every non-injection output and the final snapshot equal S04's |
| S04 | I05-4 reference: AFTER 0 alone |
| S05 | Injection queue order (model-defined): NEXT, NEXT, then AFTER 0 fails the third record attempt, because the AFTER failure queues behind pending NEXT failures |

S01 and S03 carry `equals`: every output of a non-injection event and the final snapshot equal the named reference; S02
and S04 differ from each other, so the pair shows the replacement in both directions. S05 pins the queue order, which the
README's "the (k+1)-th record attempted from then on" does not state exactly: the model queues an AFTER failure behind
pending NEXT failures. With these vectors AF2-I05-1 is closed for the v3 contract (recorded in this directory's status
record after review); the v3 bytes do not change.
