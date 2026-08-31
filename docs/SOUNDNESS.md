# VES-STARK Soundness Notes

This document summarizes what the current per-event compliance proof proves, and the key algebraic
checks that make the statement sound.

## Proven Statement (Per-Event Compliance)

Given:
- Public inputs `P` (event metadata, payload hashes, policy id/params/hash)
- A public effective policy limit `L`
- A public witness commitment `C` (4 field elements)

A valid proof attests that there exists a private witness `(amount, salt)` (a u64 amount and a
128-bit blinding salt as four u32 limbs) such that:
- `amount <= L`
- `C == Rescue([amount_lo, amount_hi, salt0..salt3, 0, 0])` (a Rescue commitment to the salted
  witness block, constrained in-AIR; a zero salt reproduces the legacy unsalted commitment
  exactly, so both schemes verify under the same circuit)
- `P` is bound to the proof instance via boundary assertions into trace columns at row 0

The salt limbs occupy trace positions AMOUNT[2..6], which are deliberately not boundary-asserted
(only AMOUNT[6..8] remain asserted zero). The comparison gadget reads only AMOUNT[0..2], so the
salt influences nothing but the Rescue sponge. A uniformly random salt makes the published
commitment *hiding*: it cannot confirm a guessed amount even over low-entropy domains.

Optional hardening: the canonical public inputs may include `witnessCommitment` (the same `C`,
hex-encoded). If present, verifiers should require it matches the proof's witness commitment to
bind the proved witness to the canonical public inputs.

Optional protocol-level hardening: the canonical public inputs may also include
`amountBindingHash`, the hash of a canonical `PayloadAmountBinding` artifact derived from the event
payload. When present, verifiers can require that artifact to match the payload hashes and witness
commitment even though the AIR does not derive the amount itself.

For `aml.threshold`, the verifier uses `L = threshold - 1` (and requires `threshold > 0`), so
`amount <= L` is equivalent to `amount < threshold`.

**V2 events (`payload_kind == 2`).** The sequencer forms
`payload_plain_hash = SHA-256(domain ‖ C ‖ restHash)`, and the verifier recomputes it natively for
the `C` the proof was verified against (`ves_stark_primitives::payload_v2`). Since the AIR proves
`C = Rescue(amount ‖ salt)`, the statement for a V2 event is that **the proved amount is the
amount on the event**, up to Rescue collision resistance — with no circuit change. This closes
the non-statement below for V2 **per-event** proofs; see `docs/AMOUNT_BINDING_DESIGN.md`.

> **Batch proofs do not yet apply this check.** `BatchVerifier` verifies the aggregate STARK and
> binds each event's public inputs, but does not recompute `SHA-256(domain ‖ C ‖ restHash)` per
> event, so a batched `payload_kind == 2` event currently carries only the V1-equivalent
> guarantee. Closing this needs the batch verifier to check the native hash against each event's
> bound `witnessCommitment`; tracked in `docs/AMOUNT_BINDING_DESIGN.md`.

Non-statement (V1 events): the AIR does **not** prove that `amount` is derived from or consistent with the
payload hashes contained in `P`. This repository now supports a canonical protocol-level binding
artifact for that purpose, but the binding still lives outside the AIR unless the proof statement
is extended.

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

### Boundary Assertions (76 total)

> Pinned by `test_air_assertions`; `docs/VERIFICATION.md` is
> checked against these numbers by `verification_matrix_test`.

The AIR binds:
- Trace framing:
  - `FLAG_IS_FIRST[0] = 1`
  - `FLAG_IS_LAST[last] = 1`
  - `ROUND_COUNTER[0] = 0`
  - `ROUND_COUNTER[last] = last`
- Effective limit limbs (u64) at row 0, plus `THRESHOLD[2..7] = 0`.
- Amount reserved limbs at row 0: `AMOUNT[6..7] = 0` (limbs 6-7 only).
  Limbs 2-5 are deliberately **unconstrained**: they carry the 128-bit blinding
  salt. Asserting them zero, as an earlier revision of this document described,
  would pin the salt to zero and destroy the hiding property.
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
This requires a minimum LDE blowup factor of 16 for the current AIR profiles in Winterfell (see
`ves_stark_air::options::ProofOptions`).

Proof security/size/performance are parameterized by `ProofOptions`:
- `default`: `num_queries=28`, `blowup_factor=16`, `grinding_factor=16`, `field_extension=None`,
  `fri_folding_factor=8`
- `fast`: `num_queries=20`, `blowup_factor=16`, `grinding_factor=8`, `field_extension=None`,
  `fri_folding_factor=8`
- `secure`: `num_queries=40`, `blowup_factor=16`, `grinding_factor=20`,
  `field_extension=Quadratic`, `fri_folding_factor=8`

The helper `ProofOptions::try_security_level()` provides an internal rough estimate; it is not a
formal security proof.

## Batch State-Transition Soundness

A batch proof (`ves-stark-batch`) attests a single statement over an ordered set of events:

> Starting from `prev_state_root`, applying these `num_events` events (each individually policy
> compliant per the per-event argument above) produces exactly `new_state_root`, the `all_compliant`
> flag correctly summarizes their compliance, and the events form a contiguous, ordered sequence
> within one tenant/store.

What the in-circuit constraints establish (all bound to `BatchPublicInputs`):

- **Per-event compliance.** Each event's amount is range-checked and compared against the policy
  limit using the same subtraction-gadget argument as the single-event proof, replicated per event
  in the batch trace.
- **Event → state-root binding.** Event leaves are hashed and Merkle-combined to an event-tree root
  in-circuit (Rescue), and the finalization rows bind `new_state_root` to a Rescue hash over
  `prev_state_root`, the event-tree root, and the batch metadata. Forging a `new_state_root`
  inconsistent with the events therefore requires breaking Rescue.
- **Compliance accumulator.** An ordered accumulator (powers of a fixed challenge) ties the public
  `all_compliant` flag to the actual per-event compliance flags, so the flag cannot be flipped
  independently of the events.
- **Ordering & structure.** Event-row/index progression constraints enforce a contiguous event
  sequence; phase constraints enforce the leaf → commitment → Merkle → finalize structure.
- **Public-input accumulator.** An ordered digest binds the per-event public inputs, so the proof
  commits to *which* events were included, in order.

Boundaries (enforced outside a single proof, by the verifier or protocol):

- **Cross-batch continuity** (a chain of batches links `new_state_root` → next `prev_state_root`,
  stays within one tenant/store, and has contiguous sequence ranges) is enforced by
  `BatchVerifier::verify_chain`, not inside one proof.
- **Proof-size bounds** are enforced before deserialization (`MAX_BATCH_PROOF_SIZE`).
- **Payload-to-amount linkage** is protocol-level, as for the single-event proof.

These properties are exercised by the batch tests catalogued in `docs/VERIFICATION.md` (§2, §3, §5).

## Hash Assumptions

Every binding property above reduces to the collision/preimage resistance of the Rescue
permutation in `ves-stark-primitives::rescue`. Two things about that primitive are worth stating
explicitly for a reviewer:

- **It is a Rescue variant, not textbook Rescue-Prime.** Textbook Rescue-Prime applies the S-box
  before the MDS in both half-rounds. Here the forward half-round is `S-box -> MDS -> +c` and the
  backward half-round is `MDS -> S-box⁻¹ -> +c`. Because the two MDS layers are then adjacent
  (separated only by a constant addition) they compose, so the matrix mixing lanes between the two
  S-box layers is `MDS²`, not `MDS`. `MDS²` is verified to retain the MDS property by
  `effective_linear_layer_between_sboxes_is_still_mds`. Published Rescue-Prime cryptanalysis does
  not transfer to this construction unchanged, and no third-party cryptanalysis of this variant
  has been performed.
- **The permutation output is pinned by known-answer tests.** `tests/rescue_kat_test.rs` holds
  vectors generated by a separate implementation, and re-derives the permutation from its
  specification in `optimized_permutation_matches_independent_reference`. This exists because the
  rest of the Rescue suite is self-referential: a defect in which the backward half-round applied
  `MDS_INV` cancelled all cross-lane diffusion and defeated commitment hiding, while every test in
  the workspace stayed green.

## Known Limitations

- Amount-to-payload binding is not enforced in the AIR today, even though protocol-level binding
  helpers are now available in this repository.
- Public inputs are bound to the proof instance, but are not used in constraints to derive or
  constrain the private witness.
- Batch proofs (`ves-stark-batch`) currently do not include a payload-to-amount linkage inside this
  crate. They do prove per-event policy compliance, policy consistency, batch ordering constraints,
  and in-circuit Merkle/finalization hashing for state transition integrity.
