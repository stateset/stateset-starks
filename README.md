# StateSet STARK

STARK proving system for VES (Verifiable Event Sync) compliance proofs.

## Overview

`stateset-stark` provides cryptographic proofs that VES events satisfy compliance policies without revealing the underlying data. Built on [Winterfell](https://github.com/facebook/winterfell), it uses STARKs (Scalable Transparent ARguments of Knowledge) for transparent, post-quantum secure proofs.

## Phase 1: Per-Event Compliance Proofs

Phase 1 implements per-event compliance proofs for:

- **Policy**: Proves that a private order amount is strictly less than a threshold
  - `aml.threshold`: amount < threshold (strict)
  - `order_total.cap`: amount <= cap (non-strict)
- **Use Case**: AML compliance (e.g., "order total < $10,000") without data exposure
- **Integration**: Works with `stateset-sequencer` proof registry

Note: The current AIR does **not** prove that the private `amount` equals a value decrypted or
parsed from the payload hashes in the public inputs. It proves a relationship about a private
`amount` witness (bound via a Rescue commitment) under the assumption that the surrounding VES
pipeline derived that witness correctly. If your sequencer/pipeline can derive a Rescue witness
commitment from the payload, include it in the canonical public inputs as `witnessCommitment` and
require it during verification to bind the proved witness to the canonical inputs.

## Architecture

```
stateset-stark/
├── crates/
│   ├── ves-stark-primitives/   # Field arithmetic, Rescue hash, public inputs
│   ├── ves-stark-air/          # AIR constraint definitions
│   ├── ves-stark-prover/       # Proof generation
│   ├── ves-stark-verifier/     # Proof verification
│   ├── ves-stark-client/       # Sequencer/Set Chain client
│   ├── ves-stark-cli/          # CLI utilities
│   └── ves-stark-batch/        # Experimental batch proofs (not yet sound)
└── tests/                       # Integration tests
```

## Usage

### Generate a Proof

```rust
use ves_stark_prover::{ComplianceProver, ComplianceWitness, Policy};

// Create witness with private amount and public inputs
let witness = ComplianceWitness::new(amount, public_inputs);

// Create prover for the policy
let policy = Policy::aml_threshold(10000);
let prover = ComplianceProver::with_policy(policy);

// Generate proof
let proof = prover.prove(&witness)?;
```

### Verify a Proof

```rust
use ves_stark_verifier::verify_compliance_proof_auto_bound;

// Requires `public_inputs.witnessCommitment` to be present to bind the proof to canonical inputs.
let result = verify_compliance_proof_auto_bound(&proof.proof_bytes, &public_inputs)?;
assert!(result.valid);
```

### Submit to Sequencer

```rust
use ves_stark_client::{ProofSubmission, SequencerClient};

let client = SequencerClient::try_new("http://localhost:8080", "api_key_here")?;

// Fetch inputs and validate the sequencer-provided hash matches the canonical hash computed locally.
let inputs = client
    .get_public_inputs_validated(event_id, "aml.threshold", 10000)
    .await?;

// Build proof
let witness = ComplianceWitness::new(amount, inputs);
let prover = ComplianceProver::with_policy(Policy::aml_threshold(10000));
let proof = prover.prove(&witness)?;

// Submit proof
let submission = ProofSubmission::aml_threshold(
    event_id,
    10000,
    proof.proof_bytes,
    proof.witness_commitment,
);
client.submit_proof(submission).await?;
```

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
  "policyHash": "hex64",
  "witnessCommitment": "hex64"
}
```

## Cryptographic Details

- **Field**: Goldilocks (64-bit prime: p = 2^64 - 2^32 + 1)
- **Hash**: Rescue-Prime (STARK-friendly, algebraic S-box)
- **Security**: target ~100-bit security with default `ProofOptions` (estimate; see `crates/ves-stark-air/src/options.rs`)
- **Proof Size**: ~100-200 KB typical

## Docs

- Soundness notes: `docs/SOUNDNESS.md`
- Threat model: `docs/THREAT_MODEL.md`
- Rescue constants (frozen + hashed): `docs/RESCUE_CONSTANTS.md`

## Building

Requires Rust `1.90.0` (pinned in `rust-toolchain.toml`).

```bash
cargo build --release
```

## Testing

```bash
cargo test
cargo test --release  # For faster proof generation
```

## Benchmarking

```bash
cargo bench
```

## License

MIT

## References

- [VES Specification](../stateset-sequencer/docs/VES.md)
- [Winterfell STARK Library](https://github.com/facebook/winterfell)
- [Rescue-Prime Paper](https://eprint.iacr.org/2020/1143)
