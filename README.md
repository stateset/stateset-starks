# StateSet STARK

STARK proving system for VES (Verifiable Event Sync) compliance proofs.

## Overview

`stateset-stark` provides witness-level cryptographic proofs that a private amount satisfies compliance policies without revealing the amount itself. Built on [Winterfell](https://github.com/facebook/winterfell), it uses STARKs (Scalable Transparent ARguments of Knowledge) for transparent, post-quantum secure proofs.

## Phase 1: Per-Event Compliance Proofs

Phase 1 implements per-event compliance proofs for:

- **Policy**: Proves that a private order amount is strictly less than a threshold
  - `aml.threshold`: amount < threshold (strict)
  - `order_total.cap`: amount <= cap (non-strict)
  - `agent.authorization.v1`: amount <= maxTotal for a delegated commerce intent hash
- **Use Case**: AML, order-cap, or delegated agent-authorization compliance for an amount witness derived by a trusted VES pipeline
- **Integration**: Works with `stateset-sequencer` proof registry

Note: The current AIR does **not** prove that the private `amount` equals a value decrypted or
parsed from the payload hashes in the public inputs. It proves a relationship about a private
`amount` witness (bound via a Rescue commitment). This repository now also provides a canonical
protocol-level `PayloadAmountBinding` artifact plus `amountBindingHash` support in public inputs so
verifiers can require a payload-derived amount binding outside the AIR.

In the `stateset-sequencer` integration, the sequencer does **not** include `witnessCommitment` in
canonical public inputs (it can't derive it pre-proof). Instead, the prover submits
`witnessCommitment` alongside the proof, and the sequencer stores it and uses it during
verification to bind the proof to the witness.

High-level local surfaces in this repository now default to stronger local verification: the CLI,
Node, and Python bindings can bind `witnessCommitment` and a canonical payload amount binding into
the public-input object before verification, and local proof artifacts can compute a bound
public-input hash that includes those local bindings. Receipt-aware helpers also derive the
payload amount binding from canonical authorization receipts instead of stopping at witness-only
binding.

For transport, `ves-stark-client` now exposes:
- `ComplianceProofBundle` for payload-bound proofs across any policy
- `AgentAuthorizationProofBundle` for delegated-commerce proofs bound to both the
  payload-derived amount artifact and the authorization receipt

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
│   └── ves-stark-batch/        # Batch proofs for aggregate state transition integrity
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
use ves_stark_verifier::verify_compliance_proof_auto_bound_strict;

// Recommended: carry `witnessCommitment` in canonical public inputs and use strict verification.
let result = verify_compliance_proof_auto_bound_strict(&proof.proof_bytes, &public_inputs)?;
assert!(result.valid);
```

For protocol-level payload binding, derive a canonical `PayloadAmountBinding`, bind it into the
public inputs, and verify against that bound object.

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
  "policyHash": "hex64"
}
```

`witnessCommitment` is optional in the public inputs format. The sequencer integration submits it
alongside the proof instead of embedding it in canonical public inputs.

For local artifacts, `compute_bound_hash()` and the batch public-input accumulator include
`witnessCommitment` when present so hashed event streams commit to the proved witness as well as the
event metadata.

Default verifier helpers accept the repository's `default` and `secure` proof profiles. The
lower-security `fast` profile is still available for tests and benchmarks, but verifiers must opt
into it explicitly with custom acceptable options.

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
cargo test --workspace --all-features
cargo test --release --workspace --all-features  # Faster proof generation
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
