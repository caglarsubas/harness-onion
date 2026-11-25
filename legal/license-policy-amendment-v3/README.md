# Licence policy amendment v3: the weights-licence class (LIC-WEIGHTS-A3)

This overlay adds one class to licence policy 0.3.0 (`legal/third-party-license-policy.yaml`):
`weightsLicenseClasses`, which classifies the licence of a model's **weights**. It never classifies code. Code stays
under the base policy's SPDX rules and the A1 and A2 overlays.

## Why an overlay, not an edit

The base policy is an immutable input. Its full sha256 is pinned in many files across the tree, most of them under
`architecture/` (MET-015's c1 claims count them at the base). An in-place edit would break every validator that reads the base as an immutable input. This is the
same reason A1 (`legal/license-policy-amendment/`) gives. So the base, A1 and A2 stay byte-identical, and this
amendment pins each of them by digest, with A1's and A2's two amendment scripts. Their two validators are pinned by
source segment, line 1 to the line before `def validate() -> None:`: each slot's catalog step moves the catalog
count inside `validate()` and nothing above it, so every rule the validators state stays pinned.

## What the class says

- The outcomes are five of the base's seven, in the base's precedence order: DENIED, UNKNOWN,
  OPTIONAL_EXPLICIT_REVIEW, ALLOWED_EXCEPTION (the base's ALLOWED_EXCEPTION_EXPRESSION) and DEFAULT_ALLOWED. The
  checker reads the names and the order from the base.
- Matching is on the pinned licence text of the weights (W-1), or on the declaration rule W-3, never on a model name or
  a card tag alone.
- W-3 needs both the README's metadata SPDX id and the card's own statement that the licence covers the weights
  (Q-W1, option 1). A W-3 row records both in `licence.declaration`.
- A restriction field that no pinned read gives is null. A row with any null restriction field is DENIED, UNKNOWN or a
  review row with no decision. It is never an allowing row: it may not be served, bundled or tenant-fetched (fail
  closed). The record lists each null by row, field and kind in `nullValues`, under the schema's one candidate-row
  null rule (`candidateNullRule` in `architecture/model-weights/schema.json`).
- The release outcomes and the distribution modes follow W-5: bundle for DEFAULT_ALLOWED and ALLOWED_EXCEPTION,
  tenant-fetched only for a review row with an approved decision, NONE otherwise.

## A stated departure from A1 and A2

A1 and A2 each landed as their own packet, with their own classifier, validator, status record, review rounds and
vectors. This overlay has none of those. It is read by one checker, `scripts/validate_model_weights.py`, the member
checker of MODEL-WEIGHTS-POLICY-001 (MET-015), which applies the class to the weights record
`architecture/model-weights/record.json`. The overlay's vectors are in `architecture/model-weights/vectors.json`.
