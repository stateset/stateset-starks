//! Fuzz target for witness validation
//!
//! This target ensures:
//! 1. Witness validation never panics
//! 2. Validation correctly rejects invalid witnesses
//! 3. Validation correctly accepts valid witnesses

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use uuid::Uuid;
use ves_stark_primitives::public_inputs::{CompliancePublicInputs, PolicyParams, compute_policy_hash};
use ves_stark_prover::ComplianceWitness;

/// Arbitrary witness input
#[derive(Debug, Arbitrary)]
struct WitnessInput {
    /// Amount to prove compliance for
    amount: u64,
    /// Threshold to compare against
    threshold: u64,
    /// Sequence number for public inputs
    sequence_number: u64,
    /// Payload kind
    payload_kind: u8,
}

fn create_public_inputs(threshold: u64, sequence_number: u64, payload_kind: u8) -> CompliancePublicInputs {
    let policy_id = "aml.threshold";
    let params = PolicyParams::threshold(threshold);
    let hash = compute_policy_hash(policy_id, &params);

    CompliancePublicInputs {
        event_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        store_id: Uuid::new_v4(),
        sequence_number,
        payload_kind: payload_kind as u64,
        payload_plain_hash: "0".repeat(64),
        payload_cipher_hash: "0".repeat(64),
        event_signing_hash: "0".repeat(64),
        policy_id: policy_id.to_string(),
        policy_params: params,
        policy_hash: hash.to_hex(),
    }
}

fuzz_target!(|input: WitnessInput| {
    // Create witness - should never panic
    let public_inputs = create_public_inputs(
        input.threshold,
        input.sequence_number,
        input.payload_kind,
    );
    let witness = ComplianceWitness::new(input.amount, public_inputs);

    // Validation should never panic
    let result = witness.validate(input.threshold);

    // Verify correctness: amount >= threshold should fail
    if input.amount >= input.threshold {
        assert!(result.is_err(), "Amount {} >= threshold {} should fail validation",
                input.amount, input.threshold);
    } else {
        // amount < threshold should succeed (assuming valid policy hash)
        assert!(result.is_ok(), "Amount {} < threshold {} should pass validation: {:?}",
                input.amount, input.threshold, result.err());
    }

    // Limb decomposition should never panic and should be correct
    let limbs = witness.amount_limbs();
    let recombined = limbs[0].as_int() | (limbs[1].as_int() << 32);
    assert_eq!(recombined, input.amount, "Limb decomposition incorrect");

    // Upper limbs should always be zero for u64 amounts
    for i in 2..8 {
        assert_eq!(limbs[i].as_int(), 0, "Upper limb {} should be zero", i);
    }
});
