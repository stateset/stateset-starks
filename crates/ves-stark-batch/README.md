# ves-stark-batch

Batch state transition proofs for VES compliance.

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
