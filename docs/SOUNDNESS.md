# VES-STARK Soundness Notes

This document summarizes what the current per-event compliance proof proves, and the key algebraic
checks that make the statement sound.

## Proven Statement (Per-Event Compliance)

Given:
- Public inputs `P` (event metadata, payload hashes, policy id/params/hash)
- A public effective policy limit `L`
- A public witness commitment `C` (4 field elements)

A valid proof attests that there exists a private witness `amount` (a u64) such that:
- `amount <= L`
- `C == Rescue(amount_limbs)` (a Rescue commitment to the witness amount limbs, constrained in-AIR)
- `P` is bound to the proof instance via boundary assertions into trace columns at row 0

Optional hardening: the canonical public inputs may include `witnessCommitment` (the same `C`,
hex-encoded). If present, verifiers should require it matches the proof's witness commitment to
bind the proved witness to the canonical public inputs.

For `aml.threshold`, the verifier uses `L = threshold - 1` (and requires `threshold > 0`), so
`amount <= L` is equivalent to `amount < threshold`.

Non-statement: the AIR does **not** prove that `amount` is derived from or consistent with the
payload hashes contained in `P`. That linkage must be enforced by the surrounding protocol/pipeline
or by extending the AIR.

## Constraint System Overview

The per-event AIR (`ComplianceAir`) is built over a power-of-two trace (minimum 128 rows).

High-level structure:
- The comparison/range gadget is enforced only at row 0 via a periodic selector `rescue_init`.
- The Rescue permutation is enforced for the first 14 transitions; after that, the Rescue state is
  constrained to remain constant.

### Transition Constraints (157 total)

- 1: round counter increment.
- 64: amount bits are binary (limbs 0-1, 32 bits each), gated to row 0.
- 2: amount limb recomposition (limbs 0-1), gated to row 0.
- 64: diff bits are binary (limbs 0-1), gated to row 0.
- 2: diff limb recomposition (limbs 0-1), gated to row 0.
- 2: borrow bits are binary (borrow0/borrow1), gated to row 0.
- 2: subtraction gadget (u64, 2 limbs), gated to row 0.
- 12: Rescue half-round transition constraints.
- 8: Rescue init binding: `state[0..7] == amount_limbs[0..7]` at row 0.

### Boundary Assertions (80 total)

The AIR binds:
- Trace framing:
  - `FLAG_IS_FIRST[0] = 1`
  - `FLAG_IS_LAST[last] = 1`
  - `ROUND_COUNTER[0] = 0`
  - `ROUND_COUNTER[last] = last`
- Effective limit limbs (u64) at row 0, plus `THRESHOLD[2..7] = 0`.
- Amount upper limbs at row 0: `AMOUNT[2..7] = 0`.
- Diff upper limbs at row 0: `DIFF[2..7] = 0`.
- Final borrow at row 0: `BORROW[1] = 0`.
- Rescue sponge domain separator / padding at row 0.
- Rescue output row (row 14): `RESCUE_STATE[0..3] == C`.
- Public input binding at row 0: `PUBLIC_INPUTS[*] == P[*]`.

## Why `amount <= limit` Holds

The AIR enforces a 2-limb subtraction witness for `limit - amount` using:
- u32 range checks (bit decomposition) for the active limbs of `amount` and `diff`,
- binary constraints for `borrow0` and `borrow1`,
- two limb-wise subtraction equations (for limbs 0 and 1),
- and a boundary assertion that `borrow1 == 0`.

Intuitively:
- The subtraction equations enforce that `limit - amount` can be represented without underflow.
- The final borrow being 0 rules out `amount > limit`.

## Why The Witness Commitment Binds `amount`

The trace includes a Rescue state column and the AIR enforces Rescue half-round transitions for a
fixed number of steps, plus initialization constraints that bind `state[0..7]` to the witness
amount limbs at row 0.

The verifier also supplies a public commitment `C`, and the AIR boundary-asserts the Rescue output
row to match `C`. Producing a valid proof for a different `amount` would require finding another
`amount'` with the same Rescue commitment (i.e., breaking the relevant Rescue security property for
the chosen parameters/output).

## Proof Options And Degrees

The Rescue constraints include an `x^7` S-box, so transition constraints include degree-7/9 terms.
This requires a minimum LDE blowup factor of 8 for soundness in Winterfell (see
`ves_stark_air::options::ProofOptions`).

Proof security/size/performance are parameterized by `ProofOptions`:
- `default`: `num_queries=28`, `blowup_factor=8`, `grinding_factor=16`, `field_extension=None`,
  `fri_folding_factor=8`
- `fast`: `num_queries=20`, `blowup_factor=8`, `grinding_factor=8`, `field_extension=None`,
  `fri_folding_factor=8`
- `secure`: `num_queries=40`, `blowup_factor=16`, `grinding_factor=20`,
  `field_extension=Quadratic`, `fri_folding_factor=8`

The helper `ProofOptions::try_security_level()` provides an internal rough estimate; it is not a
formal security proof.

## Known Limitations

- Amount-to-payload binding is not enforced in the AIR today.
- Public inputs are bound to the proof instance, but are not used in constraints to derive or
  constrain the private witness.
- Batch proofs (`ves-stark-batch`) are prototype-grade: they bind batch public inputs and enforce a
  well-formed scaled-AND accumulator over per-event compliance flags, but they do not yet verify
  Merkle transitions or per-event proof correctness.
