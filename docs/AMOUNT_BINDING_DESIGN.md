# Binding the proved amount to the event payload — design

**Status:** proposed. The circuit-side contract below is fixed enough to build
against; the sequencer-side change (how `payload_plain_hash` is formed) lives in
`stateset-sequencer` and must land first. Nothing in this document is
implemented yet.

## The gap

Today a compliance proof attests, for public inputs `P` and commitment `C`:

> there exists `(amount, salt)` with `amount <= L` and `C = Rescue(amount ‖ salt)`.

It does **not** attest that `amount` is the amount on the event whose hashes sit
in `P`. `SOUNDNESS.md` states this plainly. The current mitigation is the
`PayloadAmountBinding` artifact — a *protocol-level* attestation checked by the
verifier outside the circuit — which means the binding is only as trustworthy as
whoever signs that artifact. A prover who controls the witness can commit to
any compliant number and produce a valid proof for a non-compliant order.

This is the one property whose absence changes what a verifier may conclude.
Everything else in the hardening backlog is robustness.

## Two ways to close it

### A. Prove the amount is a substring of the hashed payload

Hash the full payload in-circuit and constrain that the canonical serialization
of `amount` appears at the right offset. Rejected: the payload is SHA-256'd by
the sequencer (`payload_plain_hash`), so this means a SHA-256 circuit — tens of
thousands of constraints per block, a different hash from everything else in
the system, and a proving-time regression of one to two orders of magnitude.

### B. Make the amount its own committed leaf — recommended

Restructure the payload commitment so the amount is a separately hashed field
that the circuit can bind to directly:

```
payload_plain_hash  =  SHA-256( domain ‖ amount_leaf ‖ rest_hash )
amount_leaf         =  Rescue( amount_lo, amount_hi, 0, 0, 0, 0, 0, 0 )      // 4 felts
rest_hash           =  SHA-256( everything in the payload except the amount )
```

The circuit already computes a Rescue permutation over the amount limbs for the
salted witness commitment. Binding then costs **one more Rescue permutation and
four boundary assertions**: constrain `amount_leaf` from the same `AMOUNT[0..2]`
limbs the comparison gadget reads, and boundary-assert its output equals the
public `amount_leaf` in `P`. No new gadgets, no new hash function in the circuit,
and the constraint-degree profile is unchanged (the Rescue block is already the
degree-10 ceiling).

The verifier then checks, natively, that `SHA-256(domain ‖ amount_leaf ‖
rest_hash) == payload_plain_hash` — a single hash over 68 bytes, no artifact and
no signer.

### What the statement becomes

> there exists `(amount, salt)` such that `amount <= L`,
> `C = Rescue(amount ‖ salt)`, **and** `amount_leaf = Rescue(amount ‖ 0)`,
> where `amount_leaf` is a component of `payload_plain_hash`.

`amount` is now the amount on the event, up to Rescue collision resistance —
the same assumption every Merkle path in the batch AIR already rests on.

## Why the leaf is unsalted

`amount_leaf` must be deterministic so the sequencer can compute it without the
prover's salt. That makes it a *binding* but *non-hiding* commitment to the
amount — which is fine, because it is never published: only `payload_plain_hash`
is, and SHA-256 over `(amount_leaf ‖ rest_hash)` hides `amount_leaf` as long as
`rest_hash` has entropy (it always does: event ids, timestamps, nonces).

The hiding property the salted witness commitment `C` provides is unchanged.

## Circuit changes (`ves-stark-air`, `ves-stark-prover`)

| Item | Change |
|---|---|
| `PUBLIC_INPUTS` | +4 field elements: `amount_leaf` |
| Trace columns | +12 (`AMOUNT_LEAF_STATE`), reuse `ROUND_COUNTER` and the existing `rescue_*` selectors |
| Transition constraints | +12 Rescue half-round + 2 init binding (`state[0..2] == AMOUNT[0..2]`, `state[2..8] == 0`) — mirrors the existing block at `compliance.rs` |
| Boundary assertions | +4: `AMOUNT_LEAF_STATE[0..4]` at row 14 == `P.amount_leaf` |
| `NUM_CONSTRAINTS` | 157 → 171; `NUM_BOUNDARY_ASSERTIONS` 76 → 80. `docs_consistency_test` will enforce both |
| Batch AIR | the per-event compliance binding (`compliance_binding.rs`) gains the same 4-element check per leaf |

Trace length stays 16 rows: the second permutation runs in parallel columns over
the same 15 rows, not after the first.

## Sequencer contract (`stateset-sequencer`)

- Compute `amount_leaf` with the same Rescue instance and limb layout as
  `ves_stark_primitives::rescue::amount_witness_commitment_salted(amount, &[0;4])`
  restricted to the first 4 output elements. Publish the exact vector in
  `docs/rescue_constants.json` alongside the existing ones.
- Emit `payload_plain_hash` as above. `domain` = `b"STATESET_VES_PAYLOAD_V2"`.
- Carry `amount_leaf` (hex, 64 chars) in the event's canonical public inputs as
  `amountLeaf`. `CompliancePublicInputs` gains the field; `payload_kind` bumps
  so V1 payloads remain verifiable under the old statement during migration.

## Migration

1. Sequencer ships V2 payload hashing behind `payload_kind = 2`; V1 unchanged.
2. `ves-stark` 0.5.0 adds the circuit block, gated on `payload_kind == 2`
   (selector column; V1 events run the old statement, unchanged constraints).
3. Verifier: for `payload_kind == 2`, the payload-binding check is the native
   SHA-256 recomputation; `PayloadAmountBinding` and
   `verify_*_with_amount_binding` become no-ops that log a deprecation.
4. Once no V1 events remain in any active batch window, drop the V1 path and the
   artifact code (0.6.0).

## Cost

Per proof: one extra 15-row Rescue block in parallel columns — roughly +12
columns, +14 constraints. Expected prove-time impact is under 10%; the batch AIR
already runs 4 Rescue blocks per leaf, so this is a fifth on the compliance
side. Measure with `cargo bench --bench stark_bench` before and after.

## Tests that must exist before this ships

- `test_amount_leaf_mismatch_rejected`: valid proof, `P.amount_leaf` swapped for
  another amount's leaf → rejected.
- `test_amount_leaf_binds_to_comparison_amount`: a trace whose leaf is computed
  from a different limb set than the comparison reads must fail the init-binding
  constraint (this is the constraint that makes the whole thing mean anything).
- KAT for `amount_leaf` in `tests/rescue_kat_test.rs`, generated by the
  independent Python implementation.
- `docs_consistency_test` updated counts.
