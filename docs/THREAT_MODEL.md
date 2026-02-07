# VES-STARK Threat Model

This document defines a concrete threat model for the current VES-STARK proof system.

## Scope

This threat model covers:
- Per-event compliance proofs (`ves-stark-air`, `ves-stark-prover`, `ves-stark-verifier`)

It explicitly does not cover:
- Batch proofs (`ves-stark-batch`) which are experimental and incomplete
- Payload encryption/decryption correctness
- Merkle/state-transition correctness outside the single-event AIR

## Statement Proven (Per-Event Compliance)

Given:
- Public inputs (event metadata, payload hashes, policy id/params/hash)
- A public witness commitment `C`

A valid proof attests that there exists a private witness `amount` (a u64) such that:
- The policy inequality holds:
  - `aml.threshold`: `amount < threshold` (implemented as `amount <= threshold - 1`)
  - `order_total.cap`: `amount <= cap`
- `C` is the Rescue commitment to the witness amount (first 4 elements of the constrained Rescue
  state after permutation).
- The provided public inputs are bound to the proof instance via boundary assertions into trace
  columns (row 0).

Optional hardening: the canonical public inputs may include `witnessCommitment` (the same `C`,
hex-encoded). If present, verifiers should require it matches the proof's witness commitment to
bind the proved witness to the canonical public inputs.

Important: the current AIR does **not** prove that `amount` is derived from, equal to, or otherwise
consistent with the payload hashes in the public inputs. That linkage must be enforced by the
surrounding protocol/pipeline (or by extending the AIR).

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
meaning "the encrypted payload's amount is compliant" unless the surrounding protocol enforces the
link (e.g., decryption/parsing + signed statement that binds `amount` to the payload hashes).

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

### 4. Policy Mismatch

Attack: generate a proof under one policy but have it verify under a different policy.

Mitigation: verifier recomputes and checks `policy_hash`, and also checks the policy id/params match
the expected policy; the AIR binds the effective limit into the trace.

### 5. Public Input Substitution

Attack: swap event metadata or payload hashes while reusing a proof.

Mitigation: the AIR binds public inputs into dedicated trace columns via boundary assertions.

Important caveat: because public inputs are not linked to `amount` inside the AIR, a malicious
prover could generate a valid proof for a chosen `amount` and arbitrary payload hashes. Preventing
this requires amount-to-payload binding in the surrounding protocol (or in the AIR).

## Security Parameters

Proof soundness and performance are determined by `ves_stark_air::options::ProofOptions`. As of
this repository version:

- `default`: `num_queries=28`, `blowup_factor=8`, `grinding_factor=16`, `field_extension=None`,
  `fri_folding_factor=8`
- `fast`: `num_queries=20`, `blowup_factor=8`, `grinding_factor=8`, `field_extension=None`,
  `fri_folding_factor=8`
- `secure`: `num_queries=40`, `blowup_factor=16`, `grinding_factor=20`,
  `field_extension=Quadratic`, `fri_folding_factor=8`

The helper `ProofOptions::try_security_level()` provides an internal rough estimate; it is not a
formal security proof.

## References

- Ben-Sasson et al., "Scalable, transparent, and post-quantum secure computational integrity"
  (STARKs)
- Grassi et al., "Rescue-Prime"
- Winterfell library documentation
