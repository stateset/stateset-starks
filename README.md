# StateSet STARK

STARK proving system for VES (Verifiable Event Sync) compliance proofs.

## Overview

`stateset-stark` provides cryptographic proofs that VES events satisfy compliance policies without revealing the underlying data. Built on [Winterfell](https://github.com/facebook/winterfell), it uses STARKs (Scalable Transparent ARguments of Knowledge) for transparent, post-quantum secure proofs.

## Phase 1: Per-Event Compliance Proofs

Phase 1 implements per-event compliance proofs for the `aml.threshold` policy:

- **Policy**: Proves that an encrypted order amount is strictly less than a threshold
- **Use Case**: AML compliance (e.g., "order total < $10,000") without data exposure
- **Integration**: Works with `stateset-sequencer` proof registry

## Architecture

```
stateset-stark/
├── crates/
│   ├── ves-stark-primitives/   # Field arithmetic, Rescue hash, public inputs
│   ├── ves-stark-air/          # AIR constraint definitions
│   ├── ves-stark-prover/       # Proof generation
│   └── ves-stark-verifier/     # Proof verification
└── tests/                       # Integration tests
```

## Usage

### Generate a Proof

```rust
use ves_stark_prover::{ComplianceProver, ComplianceWitness};
use ves_stark_air::policies::aml_threshold::AmlThresholdPolicy;

// Create witness with private amount and public inputs
let witness = ComplianceWitness::new(amount, public_inputs);

// Create prover for the policy
let policy = AmlThresholdPolicy::new(10000); // threshold
let prover = ComplianceProver::new(policy);

// Generate proof
let proof = prover.prove(&witness)?;
```

### Verify a Proof

```rust
use ves_stark_verifier::verify_compliance_proof_auto;

let result = verify_compliance_proof_auto(&proof.proof_bytes, &public_inputs, &proof.witness_commitment)?;
assert!(result.valid);
```

### Submit to Sequencer

```rust
// POST /api/v1/ves/compliance/{event_id}/proofs
let request = SubmitComplianceProofRequest {
    proof_type: "STARK",
    proof_version: 1,
    policy_id: "aml.threshold",
    policy_params: json!({"threshold": 10000}),
    proof_b64: base64::encode(&proof.proof_bytes),
    public_inputs: Some(public_inputs),
};
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
  "payloadPlainHash": "hex32",
  "payloadCipherHash": "hex32",
  "eventSigningHash": "hex32",
  "policyId": "aml.threshold",
  "policyParams": {"threshold": 10000},
  "policyHash": "hex32"
}
```

## Cryptographic Details

- **Field**: Goldilocks (64-bit prime: p = 2^64 - 2^32 + 1)
- **Hash**: Rescue-Prime (STARK-friendly, algebraic S-box)
- **Security**: ~100 bits with default options
- **Proof Size**: ~100-200 KB typical

## Building

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
