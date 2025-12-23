//! Adversarial Tests for VES-STARK Security
//!
//! These tests verify that the proof system correctly rejects various attack vectors:
//! - Policy mismatch attacks
//! - Threshold/cap manipulation
//! - Witness commitment tampering
//! - Invalid public inputs
//! - Hex format injection
//!
//! SECURITY: A passing test suite here doesn't guarantee security, but a failing
//! test indicates a potential vulnerability that must be investigated.

use ves_stark_prover::{ComplianceProver, ComplianceWitness, Policy, ComplianceProof};
use ves_stark_verifier::{verify_compliance_proof, VerifierError, validate_hex_string};
use ves_stark_primitives::public_inputs::{CompliancePublicInputs, PolicyParams, compute_policy_hash};
use uuid::Uuid;

// =============================================================================
// Test Helpers
// =============================================================================

fn sample_aml_public_inputs(threshold: u64) -> CompliancePublicInputs {
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

fn sample_cap_public_inputs(cap: u64) -> CompliancePublicInputs {
    let policy_id = "order_total.cap";
    let params = PolicyParams::cap(cap);
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

fn generate_valid_proof(amount: u64, threshold: u64) -> (ComplianceProof, CompliancePublicInputs) {
    let inputs = sample_aml_public_inputs(threshold);
    let witness = ComplianceWitness::new(amount, inputs.clone());
    let policy = Policy::aml_threshold(threshold);
    let prover = ComplianceProver::with_policy(policy);
    let proof = prover.prove(&witness).expect("Proof generation should succeed");
    (proof, inputs)
}

// =============================================================================
// Policy Mismatch Attacks
// =============================================================================

#[test]
fn test_policy_id_mismatch_rejected() {
    // Generate proof for aml.threshold policy
    let threshold = 10000u64;
    let amount = 5000u64;
    let (proof, _original_inputs) = generate_valid_proof(amount, threshold);

    // Try to verify with order_total.cap public inputs (different policy)
    let cap_inputs = sample_cap_public_inputs(threshold);
    let verify_policy = Policy::aml_threshold(threshold);

    let result = verify_compliance_proof(
        &proof.proof_bytes,
        &cap_inputs,
        &verify_policy,
        &proof.witness_commitment,
    );

    // Should fail because public inputs have different policy_id
    assert!(
        result.is_err() || !result.as_ref().unwrap().valid,
        "Verification should fail for mismatched policy_id"
    );
}

#[test]
fn test_threshold_mismatch_rejected() {
    // Generate proof for threshold 10000
    let original_threshold = 10000u64;
    let amount = 5000u64;
    let (proof, _original_inputs) = generate_valid_proof(amount, original_threshold);

    // Try to verify with different threshold in public inputs
    let different_threshold = 1000u64; // Lower threshold - attacker's goal
    let tampered_inputs = sample_aml_public_inputs(different_threshold);
    let verify_policy = Policy::aml_threshold(different_threshold);

    let result = verify_compliance_proof(
        &proof.proof_bytes,
        &tampered_inputs,
        &verify_policy,
        &proof.witness_commitment,
    );

    // Should fail because proof was generated for different threshold
    // The boundary assertions bind the threshold to the trace
    assert!(
        result.is_err() || !result.as_ref().unwrap().valid,
        "Verification should fail for mismatched threshold"
    );
}

#[test]
fn test_higher_threshold_proof_fails_lower_verification() {
    // Generate proof that amount 5000 < threshold 10000
    let original_threshold = 10000u64;
    let amount = 5000u64;
    let (proof, _original_inputs) = generate_valid_proof(amount, original_threshold);

    // Attacker tries to claim this proves amount < 1000 (which is false)
    let claimed_threshold = 1000u64;
    let tampered_inputs = sample_aml_public_inputs(claimed_threshold);
    let verify_policy = Policy::aml_threshold(claimed_threshold);

    let result = verify_compliance_proof(
        &proof.proof_bytes,
        &tampered_inputs,
        &verify_policy,
        &proof.witness_commitment,
    );

    // Must fail - can't downgrade threshold after proof generation
    assert!(
        result.is_err() || !result.as_ref().unwrap().valid,
        "Cannot verify proof with lower threshold than original"
    );
}

// =============================================================================
// Witness Commitment Tampering
// =============================================================================

#[test]
fn test_tampered_witness_commitment_rejected() {
    let threshold = 10000u64;
    let amount = 5000u64;
    let (proof, inputs) = generate_valid_proof(amount, threshold);

    // Tamper with witness commitment
    let mut tampered_commitment = proof.witness_commitment;
    tampered_commitment[0] = tampered_commitment[0].wrapping_add(1);

    let verify_policy = Policy::aml_threshold(threshold);
    let result = verify_compliance_proof(
        &proof.proof_bytes,
        &inputs,
        &verify_policy,
        &tampered_commitment,
    );

    // Should fail because commitment doesn't match trace
    assert!(
        result.is_err() || !result.as_ref().unwrap().valid,
        "Verification should fail for tampered witness commitment"
    );
}

#[test]
fn test_zero_witness_commitment_rejected() {
    let threshold = 10000u64;
    let amount = 5000u64;
    let (proof, inputs) = generate_valid_proof(amount, threshold);

    // Use zero commitment instead of real one
    let zero_commitment = [0u64; 4];

    let verify_policy = Policy::aml_threshold(threshold);
    let result = verify_compliance_proof(
        &proof.proof_bytes,
        &inputs,
        &verify_policy,
        &zero_commitment,
    );

    // Should fail because commitment doesn't match trace
    assert!(
        result.is_err() || !result.as_ref().unwrap().valid,
        "Verification should fail for zero witness commitment"
    );
}

#[test]
fn test_commitment_from_different_amount_rejected() {
    // Generate two proofs with different amounts
    let threshold = 10000u64;
    let amount1 = 5000u64;
    let amount2 = 7000u64;

    let (proof1, inputs1) = generate_valid_proof(amount1, threshold);
    let (proof2, _inputs2) = generate_valid_proof(amount2, threshold);

    // Try to use proof1's bytes with proof2's commitment
    let verify_policy = Policy::aml_threshold(threshold);
    let result = verify_compliance_proof(
        &proof1.proof_bytes,
        &inputs1,
        &verify_policy,
        &proof2.witness_commitment, // Wrong commitment
    );

    // Should fail because commitment doesn't match the proof
    assert!(
        result.is_err() || !result.as_ref().unwrap().valid,
        "Verification should fail when using commitment from different proof"
    );
}

// =============================================================================
// Hex Format Injection Attacks
// =============================================================================

#[test]
fn test_uppercase_hex_rejected() {
    // Valid lowercase hex
    assert!(validate_hex_string("test", &"a".repeat(64), 64).is_ok());

    // Uppercase should be rejected
    assert!(validate_hex_string("test", &"A".repeat(64), 64).is_err());

    // Mixed case should be rejected
    let mixed = "aAbBcCdDeEfF".repeat(6)[..64].to_string();
    assert!(validate_hex_string("test", &mixed, 64).is_err());
}

#[test]
fn test_wrong_length_hex_rejected() {
    // Too short
    assert!(validate_hex_string("test", &"a".repeat(63), 64).is_err());

    // Too long
    assert!(validate_hex_string("test", &"a".repeat(65), 64).is_err());

    // Empty
    assert!(validate_hex_string("test", "", 64).is_err());
}

#[test]
fn test_non_hex_characters_rejected() {
    // Contains non-hex characters
    let with_g = "g".repeat(64);
    assert!(validate_hex_string("test", &with_g, 64).is_err());

    // Contains spaces
    let with_spaces = format!("{} {}", "a".repeat(31), "a".repeat(32));
    assert!(validate_hex_string("test", &with_spaces, 64).is_err());

    // Contains special characters
    let with_special = format!("{}!", "a".repeat(63));
    assert!(validate_hex_string("test", &with_special, 64).is_err());
}

#[test]
fn test_invalid_policy_hash_hex_rejected() {
    let threshold = 10000u64;
    let amount = 5000u64;
    let (proof, mut inputs) = generate_valid_proof(amount, threshold);

    // Inject uppercase characters into policy hash
    inputs.policy_hash = "A".repeat(64);

    let verify_policy = Policy::aml_threshold(threshold);
    let result = verify_compliance_proof(
        &proof.proof_bytes,
        &inputs,
        &verify_policy,
        &proof.witness_commitment,
    );

    // Should fail due to hex validation
    assert!(
        matches!(result, Err(VerifierError::InvalidHexFormat { .. })),
        "Should reject uppercase hex in policy_hash"
    );
}

#[test]
fn test_invalid_payload_hash_hex_rejected() {
    let threshold = 10000u64;
    let amount = 5000u64;
    let (proof, mut inputs) = generate_valid_proof(amount, threshold);

    // Inject invalid characters into payload hash
    inputs.payload_plain_hash = "x".repeat(64);

    let verify_policy = Policy::aml_threshold(threshold);
    let result = verify_compliance_proof(
        &proof.proof_bytes,
        &inputs,
        &verify_policy,
        &proof.witness_commitment,
    );

    // Should fail due to hex validation
    assert!(
        matches!(result, Err(VerifierError::InvalidHexFormat { .. })),
        "Should reject invalid hex in payload_plain_hash"
    );
}

// =============================================================================
// Boundary Value Attacks
// =============================================================================

#[test]
fn test_amount_equals_threshold_rejected_for_lt() {
    // For aml.threshold (strict less-than), amount == threshold should fail
    let threshold = 10000u64;
    let amount = 10000u64; // Equal to threshold

    let inputs = sample_aml_public_inputs(threshold);
    let witness = ComplianceWitness::new(amount, inputs);
    let policy = Policy::aml_threshold(threshold);
    let prover = ComplianceProver::with_policy(policy);

    let result = prover.prove(&witness);

    // Should fail during proof generation
    assert!(
        result.is_err(),
        "Proof generation should fail for amount == threshold (LT policy)"
    );
}

#[test]
fn test_amount_exceeds_threshold_rejected() {
    // Amount > threshold should always fail
    let threshold = 10000u64;
    let amount = 10001u64;

    let inputs = sample_aml_public_inputs(threshold);
    let witness = ComplianceWitness::new(amount, inputs);
    let policy = Policy::aml_threshold(threshold);
    let prover = ComplianceProver::with_policy(policy);

    let result = prover.prove(&witness);

    // Should fail during proof generation
    assert!(
        result.is_err(),
        "Proof generation should fail for amount > threshold"
    );
}

#[test]
fn test_amount_exceeds_cap_rejected() {
    // For order_total.cap (LTE), amount > cap should fail
    let cap = 10000u64;
    let amount = 10001u64;

    let inputs = sample_cap_public_inputs(cap);
    let witness = ComplianceWitness::new(amount, inputs);
    let policy = Policy::order_total_cap(cap);
    let prover = ComplianceProver::with_policy(policy);

    let result = prover.prove(&witness);

    // Should fail during proof generation
    assert!(
        result.is_err(),
        "Proof generation should fail for amount > cap"
    );
}

// =============================================================================
// Proof Reuse/Replay Attacks
// =============================================================================

#[test]
fn test_proof_with_different_event_id_still_validates() {
    // NOTE: This test documents current behavior - proofs can be replayed
    // with different event IDs. This is a known limitation that should be
    // addressed by including event_id in the proof circuit.

    let threshold = 10000u64;
    let amount = 5000u64;
    let (proof, original_inputs) = generate_valid_proof(amount, threshold);

    // Create new inputs with different event_id
    let mut different_event_inputs = original_inputs.clone();
    different_event_inputs.event_id = Uuid::new_v4();

    let verify_policy = Policy::aml_threshold(threshold);
    let result = verify_compliance_proof(
        &proof.proof_bytes,
        &different_event_inputs,
        &verify_policy,
        &proof.witness_commitment,
    );

    // TODO: In a future version, this should fail!
    // Currently, the event_id is not bound to the proof circuit.
    // This is documented as a limitation.
    if let Ok(res) = result {
        println!("WARNING: Proof replay with different event_id succeeded (known limitation)");
        println!("Result valid: {}", res.valid);
    }
}

// =============================================================================
// Malformed Input Tests
// =============================================================================

#[test]
fn test_empty_proof_bytes_rejected() {
    let threshold = 10000u64;
    let inputs = sample_aml_public_inputs(threshold);
    let verify_policy = Policy::aml_threshold(threshold);
    let witness_commitment = [0u64; 4];

    let result = verify_compliance_proof(
        &[],
        &inputs,
        &verify_policy,
        &witness_commitment,
    );

    assert!(
        result.is_err(),
        "Empty proof bytes should be rejected"
    );
}

#[test]
fn test_garbage_proof_bytes_rejected() {
    let threshold = 10000u64;
    let inputs = sample_aml_public_inputs(threshold);
    let verify_policy = Policy::aml_threshold(threshold);
    let witness_commitment = [0u64; 4];
    let garbage = vec![0xFF; 1000];

    let result = verify_compliance_proof(
        &garbage,
        &inputs,
        &verify_policy,
        &witness_commitment,
    );

    assert!(
        result.is_err(),
        "Garbage proof bytes should be rejected"
    );
}

#[test]
fn test_truncated_proof_rejected() {
    let threshold = 10000u64;
    let amount = 5000u64;
    let (proof, inputs) = generate_valid_proof(amount, threshold);

    // Truncate the proof
    let truncated = &proof.proof_bytes[..proof.proof_bytes.len() / 2];

    let verify_policy = Policy::aml_threshold(threshold);
    let result = verify_compliance_proof(
        truncated,
        &inputs,
        &verify_policy,
        &proof.witness_commitment,
    );

    assert!(
        result.is_err(),
        "Truncated proof should be rejected"
    );
}

#[test]
fn test_bit_flipped_proof_rejected() {
    let threshold = 10000u64;
    let amount = 5000u64;
    let (proof, inputs) = generate_valid_proof(amount, threshold);

    // Flip a bit in the proof
    let mut corrupted = proof.proof_bytes.clone();
    if !corrupted.is_empty() {
        corrupted[0] ^= 0x01;
    }

    let verify_policy = Policy::aml_threshold(threshold);
    let result = verify_compliance_proof(
        &corrupted,
        &inputs,
        &verify_policy,
        &proof.witness_commitment,
    );

    assert!(
        result.is_err() || !result.as_ref().unwrap().valid,
        "Bit-flipped proof should be rejected"
    );
}
