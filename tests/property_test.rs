//! Property-Based Tests for VES-STARK
//!
//! These tests use proptest to verify invariants that should hold for all inputs:
//! - Valid amounts always produce valid proofs
//! - Invalid amounts never produce valid proofs
//! - Witness commitments are deterministic and binding
//! - Comparison results match native Rust comparisons

use proptest::prelude::*;
use ves_stark_prover::{ComplianceProver, ComplianceWitness, Policy};
use ves_stark_verifier::verify_compliance_proof;
use ves_stark_primitives::public_inputs::{CompliancePublicInputs, PolicyParams, compute_policy_hash};
use ves_stark_primitives::rescue::rescue_hash;
use ves_stark_primitives::{Felt, felt_from_u64};
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

/// Convert u64 amount to limbs for commitment computation
fn amount_to_limbs(amount: u64) -> [Felt; 8] {
    let low = (amount & 0xFFFFFFFF) as u64;
    let high = (amount >> 32) as u64;
    [
        felt_from_u64(low),
        felt_from_u64(high),
        felt_from_u64(0),
        felt_from_u64(0),
        felt_from_u64(0),
        felt_from_u64(0),
        felt_from_u64(0),
        felt_from_u64(0),
    ]
}

// =============================================================================
// AML Threshold Property Tests (amount < threshold)
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    /// Property: Any amount strictly less than threshold produces a valid proof
    #[test]
    fn prop_valid_amount_always_proves_lt(
        amount in 0u64..9999,
        threshold in 10000u64..100000,
    ) {
        // Ensure amount < threshold
        prop_assume!(amount < threshold);

        let inputs = sample_aml_public_inputs(threshold);
        let witness = ComplianceWitness::new(amount, inputs.clone());
        let policy = Policy::aml_threshold(threshold);
        let prover = ComplianceProver::with_policy(policy);

        let proof_result = prover.prove(&witness);
        prop_assert!(
            proof_result.is_ok(),
            "Proof generation should succeed for amount {} < threshold {}",
            amount, threshold
        );

        // Verify the proof
        let proof = proof_result.unwrap();
        let verify_result = verify_compliance_proof(
            &proof.proof_bytes,
            &inputs,
            &Policy::aml_threshold(threshold),
            &proof.witness_commitment,
        );

        prop_assert!(verify_result.is_ok());
        prop_assert!(verify_result.unwrap().valid);
    }

    /// Property: Any amount >= threshold fails proof generation
    #[test]
    fn prop_invalid_amount_never_proves_lt(
        threshold in 1u64..10000,
        excess in 0u64..1000,
    ) {
        let amount = threshold.saturating_add(excess);
        // amount >= threshold

        let inputs = sample_aml_public_inputs(threshold);
        let witness = ComplianceWitness::new(amount, inputs);
        let policy = Policy::aml_threshold(threshold);
        let prover = ComplianceProver::with_policy(policy);

        let proof_result = prover.prove(&witness);
        prop_assert!(
            proof_result.is_err(),
            "Proof generation should fail for amount {} >= threshold {}",
            amount, threshold
        );
    }

    /// Property: Boundary case - amount == threshold - 1 always succeeds
    #[test]
    fn prop_boundary_below_always_succeeds_lt(
        threshold in 2u64..10000,
    ) {
        let amount = threshold - 1;

        let inputs = sample_aml_public_inputs(threshold);
        let witness = ComplianceWitness::new(amount, inputs.clone());
        let policy = Policy::aml_threshold(threshold);
        let prover = ComplianceProver::with_policy(policy);

        let proof_result = prover.prove(&witness);
        prop_assert!(proof_result.is_ok());
    }

    /// Property: Boundary case - amount == threshold always fails (strict LT)
    #[test]
    fn prop_boundary_equal_always_fails_lt(
        threshold in 1u64..10000,
    ) {
        let amount = threshold;

        let inputs = sample_aml_public_inputs(threshold);
        let witness = ComplianceWitness::new(amount, inputs);
        let policy = Policy::aml_threshold(threshold);
        let prover = ComplianceProver::with_policy(policy);

        let proof_result = prover.prove(&witness);
        prop_assert!(
            proof_result.is_err(),
            "Proof should fail for amount == threshold (strict LT)"
        );
    }
}

// =============================================================================
// Order Total Cap Property Tests (amount <= cap)
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    /// Property: Any amount <= cap produces a valid proof
    #[test]
    fn prop_valid_amount_always_proves_lte(
        amount in 0u64..10000,
        cap in 10000u64..100000,
    ) {
        // Ensure amount <= cap
        prop_assume!(amount <= cap);

        let inputs = sample_cap_public_inputs(cap);
        let witness = ComplianceWitness::new(amount, inputs.clone());
        let policy = Policy::order_total_cap(cap);
        let prover = ComplianceProver::with_policy(policy);

        let proof_result = prover.prove(&witness);
        prop_assert!(
            proof_result.is_ok(),
            "Proof generation should succeed for amount {} <= cap {}",
            amount, cap
        );
    }

    /// Property: Any amount > cap fails proof generation
    #[test]
    fn prop_invalid_amount_never_proves_lte(
        cap in 1u64..10000,
        excess in 1u64..1000,
    ) {
        let amount = cap.saturating_add(excess);
        // amount > cap

        let inputs = sample_cap_public_inputs(cap);
        let witness = ComplianceWitness::new(amount, inputs);
        let policy = Policy::order_total_cap(cap);
        let prover = ComplianceProver::with_policy(policy);

        let proof_result = prover.prove(&witness);
        prop_assert!(
            proof_result.is_err(),
            "Proof generation should fail for amount {} > cap {}",
            amount, cap
        );
    }

    /// Property: Boundary case - amount == cap always succeeds (LTE)
    #[test]
    fn prop_boundary_equal_always_succeeds_lte(
        cap in 1u64..10000,
    ) {
        let amount = cap;

        let inputs = sample_cap_public_inputs(cap);
        let witness = ComplianceWitness::new(amount, inputs.clone());
        let policy = Policy::order_total_cap(cap);
        let prover = ComplianceProver::with_policy(policy);

        let proof_result = prover.prove(&witness);
        prop_assert!(
            proof_result.is_ok(),
            "Proof should succeed for amount == cap (LTE)"
        );
    }

    /// Property: Boundary case - amount == cap + 1 always fails
    #[test]
    fn prop_boundary_above_always_fails_lte(
        cap in 1u64..10000,
    ) {
        let amount = cap + 1;

        let inputs = sample_cap_public_inputs(cap);
        let witness = ComplianceWitness::new(amount, inputs);
        let policy = Policy::order_total_cap(cap);
        let prover = ComplianceProver::with_policy(policy);

        let proof_result = prover.prove(&witness);
        prop_assert!(
            proof_result.is_err(),
            "Proof should fail for amount > cap"
        );
    }
}

// =============================================================================
// Witness Commitment Property Tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Property: Same amount always produces same commitment (deterministic)
    #[test]
    fn prop_commitment_is_deterministic(amount in any::<u64>()) {
        let limbs = amount_to_limbs(amount);
        let input: Vec<Felt> = limbs.iter().cloned().collect();

        let hash1 = rescue_hash(&input);
        let hash2 = rescue_hash(&input);

        prop_assert_eq!(hash1, hash2, "Rescue hash should be deterministic");
    }

    /// Property: Different amounts produce different commitments (with high probability)
    #[test]
    fn prop_commitment_is_binding(
        amount1 in any::<u64>(),
        amount2 in any::<u64>(),
    ) {
        prop_assume!(amount1 != amount2);

        let limbs1 = amount_to_limbs(amount1);
        let limbs2 = amount_to_limbs(amount2);

        let input1: Vec<Felt> = limbs1.iter().cloned().collect();
        let input2: Vec<Felt> = limbs2.iter().cloned().collect();

        let hash1 = rescue_hash(&input1);
        let hash2 = rescue_hash(&input2);

        // Different inputs should produce different hashes
        // (collision probability is negligible for cryptographic hash)
        prop_assert_ne!(
            hash1, hash2,
            "Different amounts should produce different commitments"
        );
    }

    /// Property: Zero amount has a valid commitment
    #[test]
    fn prop_zero_amount_commitment(_dummy in 0u8..1) {
        let limbs = amount_to_limbs(0);
        let input: Vec<Felt> = limbs.iter().cloned().collect();
        let hash = rescue_hash(&input);

        // Hash should not be all zeros (that would be suspicious)
        let all_zero = hash.iter().all(|&x| x == felt_from_u64(0));
        prop_assert!(!all_zero, "Zero amount should not produce all-zero hash");
    }

    /// Property: Max amount has a valid commitment
    #[test]
    fn prop_max_amount_commitment(_dummy in 0u8..1) {
        let limbs = amount_to_limbs(u64::MAX);
        let input: Vec<Felt> = limbs.iter().cloned().collect();
        let hash = rescue_hash(&input);

        // Hash should exist and not panic
        prop_assert!(hash.len() == 4);
    }
}

// =============================================================================
// Policy Hash Property Tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    /// Property: Policy hash is deterministic for same inputs
    #[test]
    fn prop_policy_hash_deterministic(threshold in any::<u64>()) {
        let policy_id = "aml.threshold";
        let params = PolicyParams::threshold(threshold);

        let hash1 = compute_policy_hash(policy_id, &params).unwrap();
        let hash2 = compute_policy_hash(policy_id, &params).unwrap();

        prop_assert_eq!(hash1.to_hex(), hash2.to_hex());
    }

    /// Property: Different thresholds produce different policy hashes
    #[test]
    fn prop_different_thresholds_different_hashes(
        threshold1 in any::<u64>(),
        threshold2 in any::<u64>(),
    ) {
        prop_assume!(threshold1 != threshold2);

        let policy_id = "aml.threshold";
        let params1 = PolicyParams::threshold(threshold1);
        let params2 = PolicyParams::threshold(threshold2);

        let hash1 = compute_policy_hash(policy_id, &params1).unwrap();
        let hash2 = compute_policy_hash(policy_id, &params2).unwrap();

        prop_assert_ne!(hash1.to_hex(), hash2.to_hex());
    }

    /// Property: Different policy types produce different hashes (same limit)
    #[test]
    fn prop_different_policies_different_hashes(limit in any::<u64>()) {
        let params_threshold = PolicyParams::threshold(limit);
        let params_cap = PolicyParams::cap(limit);

        let hash_aml = compute_policy_hash("aml.threshold", &params_threshold).unwrap();
        let hash_cap = compute_policy_hash("order_total.cap", &params_cap).unwrap();

        prop_assert_ne!(hash_aml.to_hex(), hash_cap.to_hex());
    }
}

// =============================================================================
// Comparison Semantics Property Tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    /// Property: LT semantics match native Rust comparison
    #[test]
    fn prop_lt_semantics_match_native(
        amount in 0u64..20000,
        threshold in 1u64..20000,
    ) {
        let native_result = amount < threshold;

        let inputs = sample_aml_public_inputs(threshold);
        let witness = ComplianceWitness::new(amount, inputs);
        let policy = Policy::aml_threshold(threshold);
        let prover = ComplianceProver::with_policy(policy);

        let proof_succeeds = prover.prove(&witness).is_ok();

        prop_assert_eq!(
            proof_succeeds, native_result,
            "Proof success ({}) should match native comparison ({} < {} = {})",
            proof_succeeds, amount, threshold, native_result
        );
    }

    /// Property: LTE semantics match native Rust comparison
    #[test]
    fn prop_lte_semantics_match_native(
        amount in 0u64..20000,
        cap in 1u64..20000,
    ) {
        let native_result = amount <= cap;

        let inputs = sample_cap_public_inputs(cap);
        let witness = ComplianceWitness::new(amount, inputs);
        let policy = Policy::order_total_cap(cap);
        let prover = ComplianceProver::with_policy(policy);

        let proof_succeeds = prover.prove(&witness).is_ok();

        prop_assert_eq!(
            proof_succeeds, native_result,
            "Proof success ({}) should match native comparison ({} <= {} = {})",
            proof_succeeds, amount, cap, native_result
        );
    }
}

// =============================================================================
// Large Value Property Tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    /// Property: Large but valid amounts work correctly
    #[test]
    fn prop_large_valid_amounts_work(
        // Use large threshold and amount < threshold
        threshold in (u64::MAX / 2)..u64::MAX,
    ) {
        let amount = threshold.saturating_sub(1);
        prop_assume!(amount < threshold);

        let inputs = sample_aml_public_inputs(threshold);
        let witness = ComplianceWitness::new(amount, inputs.clone());
        let policy = Policy::aml_threshold(threshold);
        let prover = ComplianceProver::with_policy(policy);

        let proof_result = prover.prove(&witness);
        prop_assert!(
            proof_result.is_ok(),
            "Large valid amount {} < {} should produce valid proof",
            amount, threshold
        );
    }

    /// Property: Amount 0 always succeeds for any positive threshold
    #[test]
    fn prop_zero_amount_always_valid(threshold in 1u64..u64::MAX) {
        let amount = 0u64;

        let inputs = sample_aml_public_inputs(threshold);
        let witness = ComplianceWitness::new(amount, inputs);
        let policy = Policy::aml_threshold(threshold);
        let prover = ComplianceProver::with_policy(policy);

        let proof_result = prover.prove(&witness);
        prop_assert!(proof_result.is_ok());
    }
}
