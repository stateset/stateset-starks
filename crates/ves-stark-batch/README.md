# ves-stark-batch

> **Integrity only:** proof bytes can disclose witness amounts. This documentation describes the 0.8.0 checkout, not a guarantee of registry availability. See [the security advisory](../../docs/SECURITY_ADVISORY_AMOUNT_DISCLOSURE.md).

[![crates.io](https://img.shields.io/crates/v/ves-stark-batch.svg)](https://crates.io/crates/ves-stark-batch)
[![license](https://img.shields.io/crates/l/ves-stark-batch.svg)](../LICENSE)

Batch state transition proofs for VES compliance.

## Installation

```toml
[dependencies]
ves-stark-batch = "0.7"
```

## Overview

Proves compliance for multiple commerce events in a single STARK proof with Merkle tree state commitments. Enables efficient batch anchoring of event sequences to the Set Chain L2.

### Architecture

- **Multi-event compliance**: Proves N events satisfy their policies in one proof
- **Merkle state tree**: Events are leaves; root commits to the full batch
- **In-circuit hashing**: Rescue-Prime Merkle and finalization hashing inside the AIR
- **Ordered accumulator**: Canonical hash over per-event public inputs for deterministic verification

### Trace Layout

- **636 transition constraints** (55 base + 177 Merkle/finalize + 104 leaf hash + 151 leaf binding + 149 compliance binding)
- **145 boundary assertions**
- `ROWS_PER_MERKLE_NODE` = 15 (14 half-rounds + 1 output)
- `FINALIZE_ROWS` = 15

## Payload-bound verification

`verify_batch_proof` checks aggregate integrity and reports
`payload_binding_verified: false`. It does not establish V2 amount-to-payload
binding for every event.

Use `verify_batch_with_event_proofs(batch_bytes, batch_inputs, expected_events,
event_proofs, ProofPrivacy::AllowDisclosure)` when that binding is required.
It verifies every independent V2 proof, exact event scope/order/policy, ordered
accumulator, and the reconstructed Merkle/final state root. Supply authenticated
expected events and batch inputs independently of the prover. Missing, reordered,
substituted, or V1 event proofs are rejected. Success reports
`payload_binding_verified: true`. A confidentiality requirement is rejected.

This path retains N event proofs plus the aggregate and their verification cost.
It is not a compressed replacement for the missing aggregate AIR binding.

## Public API

```rust
use ves_stark_batch::{
    BatchProver, BatchVerifier,
    BatchWitness, BatchWitnessBuilder,
    BatchProof, BatchPublicInputs,
};

// Build witness for a batch of events
let mut builder = BatchWitnessBuilder::new();
builder.add_event(event_leaf, event_witness)?;
let witness = builder.build()?;

// Generate batch proof
let prover = BatchProver::new();
let proof = prover.prove(&witness)?;

// Verify batch proof
let verifier = BatchVerifier::new();
let result = verifier.verify(&proof, &public_inputs)?;
```

## Key Types

| Type | Description |
|------|-------------|
| `BatchProver` | Batch proof generator |
| `BatchVerifier` | Batch proof verifier |
| `BatchWitness` / `BatchWitnessBuilder` | Batch witness construction |
| `BatchEventWitness` | Per-event witness data |
| `EventLeaf` / `EventMerkleTree` | Merkle tree primitives |
| `BatchProof` / `BatchProofMetadata` | Proof output + metadata |
| `BatchPublicInputs` | Public inputs including state roots |
| `BatchStateRoot` | Merkle root commitment |
| `BatchPolicyKind` | Policy type for batch events |
| `SerializableBatchProof` | Serialization-friendly proof format |

## License

MIT
