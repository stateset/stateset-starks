# ves-stark-prover

[![crates.io](https://img.shields.io/crates/v/ves-stark-prover.svg)](https://crates.io/crates/ves-stark-prover)

STARK proof generation for VES compliance proofs.

## Overview

Generates zero-knowledge STARK proofs that attest to commerce event compliance without revealing sensitive transaction data. Produces ~42 KB proofs in ~17ms.

## Installation

```toml
[dependencies]
ves-stark-prover = "0.3"
```

## Usage

```rust
use ves_stark_prover::{ComplianceProver, ComplianceWitness, Policy};

let witness = ComplianceWitness::new(amount, public_inputs);
let prover = ComplianceProver::with_policy(Policy::aml_threshold(10_000));
let proof = prover.prove(&witness)?;

println!("Proof size: {} bytes", proof.proof_bytes.len()); // ~42 KB
println!("Commitment: {:?}", proof.witness_commitment);
```

## Supported Policies

| Policy | Description |
|--------|-------------|
| `aml.threshold` | Proves amount < threshold |
| `order_total.cap` | Proves amount <= cap |
| `agent.authorization.v1` | Proves amount <= maxTotal with intent hash binding |

## Key Types

| Type | Description |
|------|-------------|
| `ComplianceProver` | Main prover with policy support |
| `ComplianceProof` | Proof output (bytes, hash, metadata, witness commitment) |
| `ComplianceWitness` | Private witness for proof generation |
| `Policy` | Unified policy type (AML, cap, agent authorization) |
| `CompactProof` | Compact serialization format |
| `ProofJson` | JSON serialization format |

## Serialization

```rust
use ves_stark_prover::{serialize_proof, deserialize_proof_bytes, ProofFormat};

let bytes = serialize_proof(&proof, ProofFormat::Compact)?;
let proof = deserialize_proof_bytes(&bytes)?;
```

## Performance

| Metric | Value |
|--------|-------|
| Prove time | ~17ms |
| Proof size | ~42 KB |
| Trace | 248 columns x 16 rows |

## License

MIT
