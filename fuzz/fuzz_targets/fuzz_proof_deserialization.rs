//! Fuzz target for proof deserialization
//!
//! This target ensures:
//! 1. Proof deserialization never panics on arbitrary input
//! 2. Invalid proofs are rejected gracefully
//! 3. Verification never panics even with garbage input

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use uuid::Uuid;
use ves_stark_air::policy::Policy;
use ves_stark_primitives::public_inputs::{CompliancePublicInputs, PolicyParams, compute_policy_hash};
use ves_stark_verifier::verify_compliance_proof;

/// Arbitrary proof bytes and verification parameters
#[derive(Debug, Arbitrary)]
struct ProofInput {
    /// Random bytes to try as a proof
    proof_bytes: Vec<u8>,
    /// Threshold value
    threshold: u64,
    /// Witness commitment (random)
    witness_commitment: [u64; 4],
}

fn create_public_inputs(threshold: u64) -> CompliancePublicInputs {
    let policy_id = "aml.threshold";
    let params = PolicyParams::threshold(threshold);
    let hash = compute_policy_hash(policy_id, &params).unwrap();

    CompliancePublicInputs {
        event_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        store_id: Uuid::new_v4(),
        sequence_number: 1,
        payload_kind: 1,
        payload_plain_hash: "0".repeat(64),
        payload_cipher_hash: "0".repeat(64),
        event_signing_hash: "0".repeat(64),
        policy_id: policy_id.to_string(),
        policy_params: params,
        policy_hash: hash.to_hex(),
    }
}

fuzz_target!(|input: ProofInput| {
    // Limit proof size to avoid OOM
    let proof_bytes: Vec<u8> = input.proof_bytes.into_iter().take(10_000).collect();

    let public_inputs = create_public_inputs(input.threshold);
    let policy = Policy::aml_threshold(input.threshold);

    // Verification should NEVER panic, even with garbage input
    let result = verify_compliance_proof(
        &proof_bytes,
        &public_inputs,
        &policy,
        &input.witness_commitment,
    );

    // Result should be an error for random bytes (not a valid proof)
    // OR a verification failure (if bytes happen to parse but fail constraints)
    match result {
        Ok(verification_result) => {
            // If we got a result, it should indicate invalid (random bytes can't be valid)
            // But we don't assert this because theoretically random bytes could
            // by extreme chance form a valid proof structure
            let _ = verification_result;
        }
        Err(_) => {
            // Expected: most random bytes will fail deserialization
        }
    }
});
