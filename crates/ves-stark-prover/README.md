# ves-stark-prover

STARK proof generation for VES compliance proofs.

## Overview

Generates zero-knowledge STARK proofs that attest to commerce event compliance without revealing sensitive transaction data. Supports multiple policy types and produces proofs suitable for on-chain verification.

## Supported Policies

| Policy | Description |
|--------|-------------|
| `aml.threshold` | Proves amount < threshold |
| `order_total.cap` | Proves amount <= cap |
| `agent.authorization.v1` | Proves amount <= maxTotal with intent hash binding |

## Public API

```rust
use ves_stark_prover::{
    ComplianceProver,
    ComplianceProof,
    ComplianceWitness,
    Policy,
};

// Create prover with policy
let policy = Policy::aml_threshold(10_000)?;
let prover = ComplianceProver::new(policy);

// Generate proof
let proof = prover.prove(&witness, &public_inputs)?;

// Access proof data
println!("Proof size: {} bytes", proof.proof_bytes.len());
println!("Hash: {}", proof.hash);
```

## Key Types

| Type | Description |
|------|-------------|
| `ComplianceProver` | Main prover with policy support |
| `ComplianceProof` | Proof output (bytes, hash, metadata, witness commitment) |
| `ComplianceWitness` | Private witness for proof generation |
| `ProofMetadata` | Proof timing and size info |
| `CompactProof` | Compact serialization format |
| `ProofJson` | JSON serialization format |

## Serialization

```rust
use ves_stark_prover::{serialize_proof, deserialize_proof_bytes, ProofFormat};

let bytes = serialize_proof(&proof, ProofFormat::Compact)?;
let proof = deserialize_proof_bytes(&bytes)?;
```

## License

MIT
