# StateSet STARK

[![crates.io](https://img.shields.io/crates/v/ves-stark-prover.svg)](https://crates.io/crates/ves-stark-prover)
[![license](https://img.shields.io/crates/l/ves-stark-prover.svg)](LICENSE)

STARK proving system for VES (Verifiable Event Sync) compliance proofs.

## Overview

`stateset-stark` provides witness-level cryptographic proofs that a private amount satisfies compliance policies without revealing the amount itself. Built on [Winterfell](https://github.com/facebook/winterfell), it uses STARKs (Scalable Transparent ARguments of Knowledge) for transparent, post-quantum secure proofs.

### Performance (v0.3.3)

| Metric | Value |
|--------|-------|
| **Prove time** | ~17ms |
| **Proof size** | ~42 KB |
| **Verify time** | <5ms |
| **Security** | 82-bit (configurable up to 128-bit) |
| **Field** | Goldilocks (p = 2^64 - 2^32 + 1) |
| **Hash** | Rescue-Prime (7 rounds, alpha=7) |

## Supported Policies

| Policy | Description |
|--------|-------------|
| `aml.threshold` | Proves amount < threshold (strict) |
| `order_total.cap` | Proves amount <= cap (non-strict) |
| `agent.authorization.v1` | Proves amount <= maxTotal for a delegated commerce intent hash |

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
ves-stark-prover = "0.3"
ves-stark-verifier = "0.3"
ves-stark-primitives = "0.3"
```

### Generate a Proof

```rust
use ves_stark_prover::{ComplianceProver, ComplianceWitness, Policy};

// Create witness with private amount and public inputs
let witness = ComplianceWitness::new(amount, public_inputs);

// Create prover for the policy
let policy = Policy::aml_threshold(10000);
let prover = ComplianceProver::with_policy(policy);

// Generate proof (~17ms)
let proof = prover.prove(&witness)?;
println!("Proof size: {} bytes", proof.proof_bytes.len()); // ~42 KB
```

### Verify a Proof

```rust
use ves_stark_verifier::verify_compliance_proof_auto_bound_strict;

let result = verify_compliance_proof_auto_bound_strict(&proof.proof_bytes, &public_inputs)?;
assert!(result.valid);
```

### Submit to Sequencer

```rust
use ves_stark_client::{ProofSubmission, SequencerClient};

let client = SequencerClient::try_new("http://localhost:8080", "api_key_here")?;

let inputs = client
    .get_public_inputs_validated(event_id, "aml.threshold", 10000)
    .await?;

let witness = ComplianceWitness::new(amount, inputs);
let prover = ComplianceProver::with_policy(Policy::aml_threshold(10000));
let proof = prover.prove(&witness)?;

let submission = ProofSubmission::aml_threshold(
    event_id, 10000, proof.proof_bytes, proof.witness_commitment,
);
client.submit_proof(submission).await?;
```

## Architecture

```
stateset-stark/
├── crates/
│   ├── ves-stark-primitives/   # Field arithmetic, Rescue hash, public inputs
│   ├── ves-stark-air/          # AIR constraint definitions (157 constraints)
│   ├── ves-stark-prover/       # Proof generation
│   ├── ves-stark-verifier/     # Proof verification
│   ├── ves-stark-batch/        # Batch proofs for aggregate state transitions
│   ├── ves-stark-client/       # Sequencer/Set Chain HTTP client
│   ├── ves-stark-cli/          # CLI tool (binary: ves-stark)
│   ├── ves-stark-wasm/         # WebAssembly bindings
│   ├── ves-stark-nodejs/       # Node.js bindings (@stateset/ves-stark)
│   ├── ves-stark-python/       # Python bindings (ves_stark)
│   └── ves-stark-zig/          # C FFI / Zig bindings
└── tests/                       # Integration tests
```

All crates are published on [crates.io](https://crates.io/search?q=ves-stark) at version 0.3.3.

## Public Inputs Format

Canonical public inputs (RFC 8785 JCS canonicalized):

```json
{
  "eventId": "uuid",
  "tenantId": "uuid",
  "storeId": "uuid",
  "sequenceNumber": 123,
  "payloadKind": 1,
  "payloadPlainHash": "hex64",
  "payloadCipherHash": "hex64",
  "eventSigningHash": "hex64",
  "policyId": "aml.threshold",
  "policyParams": {"threshold": 10000},
  "policyHash": "hex64"
}
```

`witnessCommitment` is optional in the public inputs format. The sequencer integration submits it
alongside the proof instead of embedding it in canonical public inputs.

## Witness Binding

The AIR proves a relationship about a private `amount` witness bound via a Rescue commitment. It does **not** prove that the amount was decrypted from the payload hashes in the public inputs. That linkage is handled by the surrounding protocol:

- **`PayloadAmountBinding`**: canonical protocol-level artifact binding the payload-derived amount
- **`amountBindingHash`**: public input field for verifiers requiring payload-derived amount binding
- **Authorization receipts**: for `agent.authorization.v1`, the receipt binds the intent hash and amount

## Cryptographic Details

| Parameter | Value |
|-----------|-------|
| Field | Goldilocks (64-bit prime: p = 2^64 - 2^32 + 1) |
| Hash | Rescue-Prime (7 rounds, state width 12, rate 8, capacity 4) |
| S-box | x^7 (forward), x^{alpha_inv} (backward) |
| MDS | 12x12 circulant matrix |
| Trace | 248 columns x 16 rows |
| Constraints | 157 transition + 80 boundary |
| FRI queries | 18 (4 bits/query) |
| Grinding | 10-bit proof-of-work |
| Blowup | 16x |
| Security | ~82 bits (default), ~128 bits (secure preset) |

## Proof Options

```rust
use ves_stark_air::ProofOptions;

let default = ProofOptions::default();  // ~82-bit security, ~17ms prove
let fast    = ProofOptions::fast();     // Lower security, faster
let secure  = ProofOptions::secure();   // ~128-bit security, larger proofs
```

## Building

Requires Rust `1.90.0` (pinned in `rust-toolchain.toml`).

```bash
cargo build --release
```

Language bindings:

```bash
cargo build -p ves-stark-wasm --target wasm32-unknown-unknown --release  # WebAssembly
cd crates/ves-stark-nodejs && npm run build                               # Node.js
cd crates/ves-stark-python && maturin develop --release                   # Python
```

## Testing

```bash
cargo test --release -p ves-stark-primitives -p ves-stark-air -p ves-stark-prover -p ves-stark-verifier --lib
```

## Benchmarking

```bash
cargo bench --bench stark_bench
```

## Docs

- Soundness notes: `docs/SOUNDNESS.md`
- Threat model: `docs/THREAT_MODEL.md`
- Rescue constants (frozen + hashed): `docs/RESCUE_CONSTANTS.md`

## License

MIT

## References

- [VES Specification](../stateset-sequencer/docs/VES.md)
- [Winterfell STARK Library](https://github.com/facebook/winterfell)
- [Rescue-Prime Paper](https://eprint.iacr.org/2020/1143)
