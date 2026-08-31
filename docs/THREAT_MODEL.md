# VES-STARK Threat Model

This document defines a concrete threat model for the current VES-STARK proof system.

## Scope

This threat model covers:
- Per-event compliance proofs (`ves-stark-air`, `ves-stark-prover`, `ves-stark-verifier`)
- Batch proofs (`ves-stark-batch`) for state-transition integrity and aggregate compliance enforcement

It explicitly does not cover:
- Payload encryption/decryption correctness
- Payload-to-amount linkage inside the AIR

## Statement Proven (Per-Event Compliance)

Given:
- Public inputs (event metadata, payload hashes, policy id/params/hash)
- A public witness commitment `C`

A valid proof attests that there exists a private witness `(amount, salt)` — a u64 amount and a
128-bit blinding salt carried as four u32 limbs — such that:
- The policy inequality holds:
  - `aml.threshold`: `amount < threshold` (implemented as `amount <= threshold - 1`)
  - `order_total.cap`: `amount <= cap`
- `C` is the Rescue commitment to the salted witness block
  `C == Rescue([amount_lo, amount_hi, salt0..salt3, 0, 0])` (first 4 elements of the constrained
  Rescue state after permutation). A zero salt reproduces the legacy unsalted commitment exactly,
  so both schemes verify under the same circuit.

The salt occupies trace positions `AMOUNT[2..6]`, which are deliberately not boundary-asserted;
the comparison gadget reads only `AMOUNT[0..2]`. A uniformly random salt therefore makes `C`
*hiding* as well as binding: it cannot confirm a guessed amount even over a low-entropy domain.
See `docs/SOUNDNESS.md` for the full argument.
- The provided public inputs are bound to the proof instance via boundary assertions into trace
  columns (row 0).

Optional hardening: the canonical public inputs may include `witnessCommitment` (the same `C`,
hex-encoded). If present, verifiers should require it matches the proof's witness commitment to
bind the proved witness to the canonical public inputs.

Optional protocol-level hardening: the canonical public inputs may also include
`amountBindingHash`, the hash of a canonical `PayloadAmountBinding` artifact derived from the event
payload. When present, verifiers should require the binding artifact to match the event metadata,
payload hashes, and witness commitment.

Repository hardening note: the CLI and the Node/Python bindings now bind `witnessCommitment` into
the public-input object before verification by default, and local bound-hash helpers include that
field in hashed artifacts.

Important: the current AIR still does **not** prove that `amount` is derived from, equal to, or
otherwise consistent with the payload hashes in the public inputs. This repository now supports a
canonical protocol-level binding artifact for that purpose, but the payload parser/derivation logic
and any signatures or attestations around it remain part of the surrounding protocol.

## Upstream Vulnerabilities (Winterfell deserialization) — contained

Both were found by `cargo +nightly fuzz run fuzz_proof_deserialization` and are
reachable from the public verifier API with well under `MAX_PROOF_SIZE` bytes.
Neither is a soundness break — a malformed proof is still never *accepted* — both
were availability defects on a surface that accepts input from anyone. Both are now
contained in-repo; the upstream code is unchanged.

### 1. Integer overflow on the trace-length byte — CONTAINED

`winter-air-0.10.3`, `src/air/trace_info.rs:311`. The deserializer validates only
the *lower* bound of the log2 trace-length byte:

```rust
let trace_length = source.read_u8()?;
if trace_length < TraceInfo::MIN_TRACE_LENGTH.ilog2() as u8 { return Err(..) }
let trace_length = 2_usize.pow(trace_length as u32);   // n up to 255
```

There is no `MAX_TRACE_LENGTH` constant in the crate, so any byte >= 64
overflows. Eleven bytes are enough to reach it.

*Impact.* Under `overflow-checks = true` (the default for debug and test builds,
and a common hardening choice for release builds of security-critical services)
this panics. With `panic = "abort"` it would kill the process.

*Mitigation, in place.* Both verifiers wrap deserialization in
`ves_stark_primitives::panic_guard::guard_untrusted`, converting the panic into a
`DeserializationError`. This is why this workspace's release profile
deliberately does not set `panic = "abort"` — the guard needs unwinding.
Regression tests: `tests/untrusted_input_test.rs`.

### 2. Unbounded allocation from a length prefix — CONTAINED

`winter-utils-0.10.2`, `src/serde/byte_reader.rs:194`:

```rust
fn read_many<D>(&mut self, num_elements: usize) -> Result<Vec<D>, DeserializationError> {
    let mut result = Vec::with_capacity(num_elements);   // never bounded by bytes remaining
```

`num_elements` is a length prefix read straight from the input. A 39-byte proof
can declare 2^56 elements; the measured request was 72,057,607,577,400,833 bytes
(~72 PB). Rust aborts on allocation failure rather than unwinding, so this was
confirmed to SIGABRT in both debug and release, and no `catch_unwind` could
contain it. Still present in the latest upstream release (`winter-air 0.13.1`).

*Mitigation, in place.* `read_many` is a *provided* method of the `ByteReader`
trait, and `Deserializable::read_from` accepts any reader — so
`ves_stark_primitives::bounded_reader::BoundedReader` overrides `read_many` to
reject any declared count larger than the bytes remaining (every element needs
at least one byte) before allocating. Both verifiers parse through
`deserialize_bounded` instead of `Proof::from_bytes`. The upstream deserializers
are otherwise unchanged; this is the same code path with a bound.
Regression test: `oversized_declared_allocation_is_rejected_not_attempted`.

*Still worth doing.* Report both bounds upstream — every Winterfell consumer that
calls `Proof::from_bytes` on untrusted input has this abort.

## Adversary Model

### Threat Actors

- Malicious prover: controls witness and trace generation and attempts to produce a verifying proof
  for a false statement.
- Network attacker: can replay or tamper with proof/public-input bytes in transit.
- Malicious verifier: can choose verification parameters; mitigations rely on verifiers enforcing
  acceptable proof options.

### Adversary Goals

- Forge a proof for a non-compliant amount.
- Mismatch the policy (prove under one policy, verify under another).
- Tamper with public inputs (event metadata / payload hashes) while keeping the proof valid.

## Security Properties (Expected To Hold)

### Soundness (Inequality)

If the verifier accepts, then with overwhelming probability there exists a witness `amount` that
satisfies the enforced inequality (under standard STARK assumptions and the configured proof
options).

### Witness Binding

The proof includes constraints for the Rescue permutation, and boundary-asserts the Rescue output
row to match the public commitment `C`. This binds the witness `amount` (limbs) to `C`.

### Range Validity (u64)

The AIR range-checks the active limbs:
- Amount limbs 0-1 and diff limbs 0-1 are constrained via 32-bit bit decomposition.
- Upper limbs 2-7 are boundary-asserted to 0.

### Policy Binding

The verifier checks the policy hash and policy parameters and the AIR binds the effective policy
limit into the trace via boundary assertions.

## Out Of Scope / Assumptions

### Amount-to-Payload Binding

The AIR does not bind `amount` to payload hashes. Applications must not interpret a valid proof as
meaning "the encrypted payload's amount is compliant" unless the surrounding protocol also enforces
the link. This repository now provides a canonical `PayloadAmountBinding` artifact and
`amountBindingHash` public-input support for that protocol-level enforcement.

### Replay Protection

Replay protection is an application-level property. The public inputs include event identifiers,
but verifiers/services must still enforce uniqueness and correct sequencing.

## Attack Vectors And Mitigations

### 1. Non-Binary Bit Manipulation

Attack: set "bit" columns to non-binary values to fake a range proof.

Mitigation: AIR enforces `b * (1 - b) = 0` for every bit column (gated to row 0).

### 2. Subtraction Gadget Manipulation

Attack: provide incorrect diff/borrow values to claim `amount <= limit` when `amount > limit`.

Mitigation: limb-wise subtraction constraints plus borrow binary constraints, and a boundary
assertion that the final borrow is 0.

### 3. Commitment Forgery

Attack: provide a commitment `C` unrelated to the actual witness.

Mitigation: Rescue permutation constraints + boundary assertion on the Rescue output row.

### 3b. Commitment Guess-Confirmation (Dictionary Attack)

Attack: the published commitment is a deterministic hash of the amount, and amounts are
low-entropy — an observer hashes candidate amounts and compares against `C` to recover the
witness without breaking any primitive.

Mitigation: the salted commitment scheme. `C = Rescue([amount_lo, amount_hi, salt0..salt3, 0, 0])`
with a fresh random 128-bit salt (`ComplianceWitness::new_salted` / the `proveSalted` WASM
export). The salt is private witness data — zeroized after proving, never serialized, never
needed by verifiers. Salting also makes two commitments to the same amount unlinkable. The
legacy zero-salt form remains verifiable but should not be published; see
`tests/salted_commitment_test.rs` for the dictionary-attack regression.

> **RESOLVED (permutation diffusion).** An earlier `rescue.rs` applied
> `MDS_INV` in the backward half-round, cancelling the forward `MDS` and
> collapsing the permutation into independent per-lane maps — so the salt
> never reached the amount lanes and the amount was recoverable from a
> published commitment. Fixed: the backward half-round now applies `MDS`
> (standard Rescue-Prime); the native permutation and the in-circuit AIR
> constraint (`compliance.rs`) were changed together and re-verified, and
> `rescue.rs::diffusion_regression` now asserts full cross-lane diffusion and
> non-recoverability of the amount from a salted commitment. The same fix
> also repaired a second consequence: `rescue_hash_pair` (the batch prover's
> Rescue-Merkle 2-to-1 compression) previously ignored its right child — now
> both children bind (regression: `rescue_hash_pair_binds_both_children`).
> Existing proofs generated under the old permutation no longer verify
> (expected).

### 4. Policy Mismatch

Attack: generate a proof under one policy but have it verify under a different policy.

Mitigation: verifier recomputes and checks `policy_hash`, and also checks the policy id/params match
the expected policy; the AIR binds the effective limit into the trace.

### 5. Public Input Substitution

Attack: swap event metadata or payload hashes while reusing a proof.

Mitigation: the AIR binds public inputs into dedicated trace columns via boundary assertions.

Important caveat: because public inputs are not linked to `amount` inside the AIR, a malicious
prover could still generate a valid proof for a chosen `amount` and arbitrary payload hashes unless
verifiers also require a matching protocol-level payload amount binding. Preventing this entirely
inside the proof statement would require extending the AIR.

When applications maintain ordered streams of public-input hashes locally, they should prefer the
bound public-input hash that includes `witnessCommitment` so the stream commits to the proved
witness as well as the event metadata.

### 6. Batch Public-Input Substitution

Attack: present a valid batch proof while claiming a different `new_state_root` (the value anchored
on-chain), `prev_state_root`, `all_compliant` flag, `policy_limit`, `batch_id`, or public-inputs
accumulator.

Mitigation: the batch AIR binds every one of these into the proof instance via the
`BatchPublicInputs` passed to verification; the STARK fails if any bound field is altered. This
binding is regression-tested by adversarial tests that tamper each field and confirm rejection.

### 7. Batch Chain Stitching

Attack: assemble a "valid" state chain from batches that do not actually follow one another — for
example, batches belonging to different tenants/stores, with sequence gaps, or whose state roots do
not link.

Mitigation: `BatchVerifier::verify_chain` verifies each batch individually and then enforces, between
consecutive batches: (a) the same tenant and store, (b) sequence continuity (`prev.sequence_end + 1
== curr.sequence_start`, with overflow checks), and (c) state-root linkage (`curr.prev_state_root ==
prev.new_state_root`). A mismatch on any of these is rejected (`InvalidStateChain` /
`InvalidPublicInputs`), preventing unrelated batches from being stitched together by coincidental
sequence numbers.

### 8. Oversized-Proof Resource Exhaustion

Attack: submit an enormous proof blob to exhaust verifier or submission resources.

Mitigation: batch verification rejects proofs larger than `MAX_BATCH_PROOF_SIZE` (10 MiB) before
attempting deserialization, and `BatchProofSubmission::validate()` rejects oversized proofs
client-side before they are sent for on-chain anchoring (the two limits are held equal by a
compile-time assertion).

## Security Parameters

Proof soundness and performance are determined by `ves_stark_air::options::ProofOptions`. As of
this repository version:

- `default`: `num_queries=28`, `blowup_factor=16`, `grinding_factor=16`, `field_extension=None`,
  `fri_folding_factor=8`
- `fast`: `num_queries=20`, `blowup_factor=16`, `grinding_factor=8`, `field_extension=None`,
  `fri_folding_factor=8`
- `secure`: `num_queries=40`, `blowup_factor=16`, `grinding_factor=20`,
  `field_extension=Quadratic`, `fri_folding_factor=8`

Default verifier helpers in this repository accept `default` and `secure` profiles only.
Verifiers that want to admit `fast` proofs must opt into that profile explicitly with custom
acceptable options.

The helper `ProofOptions::try_security_level()` provides an internal rough estimate; it is not a
formal security proof.

## References

- Ben-Sasson et al., "Scalable, transparent, and post-quantum secure computational integrity"
  (STARKs)
- Grassi et al., "Rescue-Prime"
- Winterfell library documentation
