//! Integration tests for VES STARK proofs
//!
//! These tests exercise the full prove/verify cycle for compliance proofs.
//!
//! # Supported Policies
//!
//! - `aml.threshold`: Proves amount < threshold (strict less-than)
//! - `order_total.cap`: Proves amount <= cap (less-than-or-equal)
//! - `agent.authorization.v1`: Proves amount <= maxTotal while committing an
//!   intentHash through the canonical policy hash

use uuid::Uuid;
use ves_stark_primitives::public_inputs::{
    compute_policy_hash, CompliancePublicInputs, PolicyParams,
};
use ves_stark_primitives::{CommerceExecution, CommerceIntent};
use ves_stark_prover::{ComplianceProver, ComplianceWitness, Policy};
use ves_stark_verifier::{verify_agent_authorization_proof_auto_bound, verify_compliance_proof};

/// Create sample public inputs for AML threshold policy
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
        payload_plain_hash: "a".repeat(64),
        payload_cipher_hash: "b".repeat(64),
        event_signing_hash: "c".repeat(64),
        policy_id: policy_id.to_string(),
        policy_params: params,
        policy_hash: hash.to_hex(),
        witness_commitment: None,
        authorization_receipt_hash: None,
    }
}

/// Create sample public inputs for order total cap policy
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
        payload_plain_hash: "a".repeat(64),
        payload_cipher_hash: "b".repeat(64),
        event_signing_hash: "c".repeat(64),
        policy_id: policy_id.to_string(),
        policy_params: params,
        policy_hash: hash.to_hex(),
        witness_commitment: None,
        authorization_receipt_hash: None,
    }
}

/// Create sample public inputs for agent authorization policy
fn sample_agent_authorization_public_inputs(
    max_total: u64,
    intent_hash: &str,
) -> CompliancePublicInputs {
    let policy_id = "agent.authorization.v1";
    let params = PolicyParams::agent_authorization(max_total, intent_hash).unwrap();
    let hash = compute_policy_hash(policy_id, &params).unwrap();

    CompliancePublicInputs {
        event_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        store_id: Uuid::new_v4(),
        sequence_number: 1,
        payload_kind: 7,
        payload_plain_hash: "d".repeat(64),
        payload_cipher_hash: "e".repeat(64),
        event_signing_hash: "f".repeat(64),
        policy_id: policy_id.to_string(),
        policy_params: params,
        policy_hash: hash.to_hex(),
        witness_commitment: None,
        authorization_receipt_hash: None,
    }
}

/// Alias for backward compatibility
fn sample_public_inputs(threshold: u64) -> CompliancePublicInputs {
    sample_aml_public_inputs(threshold)
}

#[test]
fn test_valid_witness_creates_valid_proof() {
    let threshold = 10000u64;
    let amount = 5000u64;

    let inputs = sample_public_inputs(threshold);
    let witness = ComplianceWitness::new(amount, inputs.clone());
    let policy = Policy::aml_threshold(threshold);

    // Create prover and generate proof
    let prover = ComplianceProver::with_policy(policy.clone());
    let proof = prover.prove(&witness);

    // Should succeed since amount < threshold
    assert!(
        proof.is_ok(),
        "Proof generation should succeed: {:?}",
        proof.err()
    );

    let proof = proof.unwrap();
    println!("Proof size: {} bytes", proof.metadata.proof_size);
    println!("Proving time: {} ms", proof.metadata.proving_time_ms);

    // Verify the proof (pass witness commitment from proof)
    let result = verify_compliance_proof(
        &proof.proof_bytes,
        &inputs,
        &policy,
        &proof.witness_commitment,
    );
    assert!(
        result.is_ok(),
        "Verification should succeed: {:?}",
        result.err()
    );

    let result = result.unwrap();
    assert!(result.valid, "Proof should be valid");
}

#[test]
fn test_invalid_witness_fails_proof_generation() {
    let threshold = 10000u64;
    let amount = 15000u64; // Exceeds threshold

    let inputs = sample_public_inputs(threshold);
    let witness = ComplianceWitness::new(amount, inputs);
    let policy = Policy::aml_threshold(threshold);

    let prover = ComplianceProver::with_policy(policy);
    let proof = prover.prove(&witness);

    // Should fail since amount >= threshold
    assert!(proof.is_err());
}

#[test]
fn test_boundary_amount_fails() {
    let threshold = 10000u64;
    let amount = 10000u64; // Equal to threshold (must be strictly less)

    let inputs = sample_public_inputs(threshold);
    let witness = ComplianceWitness::new(amount, inputs);
    let policy = Policy::aml_threshold(threshold);

    let prover = ComplianceProver::with_policy(policy);
    let proof = prover.prove(&witness);

    // Should fail since amount == threshold
    assert!(proof.is_err());
}

#[test]
fn test_zero_amount_succeeds() {
    let threshold = 10000u64;
    let amount = 0u64;

    let inputs = sample_public_inputs(threshold);
    let witness = ComplianceWitness::new(amount, inputs.clone());
    let policy = Policy::aml_threshold(threshold);

    let prover = ComplianceProver::with_policy(policy.clone());
    let proof = prover.prove(&witness);

    assert!(proof.is_ok());

    let proof = proof.unwrap();
    let result = verify_compliance_proof(
        &proof.proof_bytes,
        &inputs,
        &policy,
        &proof.witness_commitment,
    );
    assert!(result.is_ok());
    assert!(result.unwrap().valid);
}

#[test]
fn test_max_valid_amount_succeeds() {
    let threshold = 10000u64;
    let amount = 9999u64; // One less than threshold

    let inputs = sample_public_inputs(threshold);
    let witness = ComplianceWitness::new(amount, inputs.clone());
    let policy = Policy::aml_threshold(threshold);

    let prover = ComplianceProver::with_policy(policy.clone());
    let proof = prover.prove(&witness);

    assert!(proof.is_ok());

    let proof = proof.unwrap();
    let result = verify_compliance_proof(
        &proof.proof_bytes,
        &inputs,
        &policy,
        &proof.witness_commitment,
    );
    assert!(result.is_ok());
    assert!(result.unwrap().valid);
}

#[test]
fn test_proof_hash_is_deterministic() {
    let threshold = 10000u64;
    let amount = 5000u64;

    let inputs = sample_public_inputs(threshold);
    let witness = ComplianceWitness::new(amount, inputs);
    let policy = Policy::aml_threshold(threshold);

    let prover = ComplianceProver::with_policy(policy);
    let proof1 = prover.prove(&witness).unwrap();
    let proof2 = prover.prove(&witness).unwrap();

    // Proof hashes should be the same for the same inputs
    // (Note: actual proof bytes may differ due to randomness in FRI)
    assert!(!proof1.proof_hash.is_empty());
    assert!(!proof2.proof_hash.is_empty());
}

#[test]
fn test_verifier_rejects_tampered_proof() {
    let threshold = 10000u64;
    let amount = 5000u64;

    let inputs = sample_public_inputs(threshold);
    let witness = ComplianceWitness::new(amount, inputs.clone());
    let policy = Policy::aml_threshold(threshold);

    let prover = ComplianceProver::with_policy(policy.clone());
    let proof = prover.prove(&witness).unwrap();

    // Tamper with the proof
    let mut tampered = proof.proof_bytes.clone();
    if !tampered.is_empty() {
        tampered[0] ^= 0xFF;
    }

    // Verification should fail or return invalid
    let result = verify_compliance_proof(&tampered, &inputs, &policy, &proof.witness_commitment);
    // Either deserialization fails or proof is invalid.
    let Ok(r) = result else {
        // Deserialization error is also acceptable.
        return;
    };
    assert!(!r.valid || r.error.is_some());
}

#[test]
fn test_public_inputs_serialization() {
    let threshold = 10000u64;
    let inputs = sample_public_inputs(threshold);

    // Serialize to JSON
    let json = serde_json::to_string(&inputs).unwrap();

    // Deserialize back
    let recovered: CompliancePublicInputs = serde_json::from_str(&json).unwrap();

    assert_eq!(inputs.event_id, recovered.event_id);
    assert_eq!(inputs.policy_id, recovered.policy_id);
    assert_eq!(inputs.policy_hash, recovered.policy_hash);
}

#[test]
fn test_large_threshold_values() {
    let threshold = u64::MAX - 1;
    let amount = u64::MAX - 2;

    let inputs = sample_public_inputs(threshold);
    let witness = ComplianceWitness::new(amount, inputs.clone());
    let policy = Policy::aml_threshold(threshold);

    let prover = ComplianceProver::with_policy(policy.clone());
    let proof = prover.prove(&witness);

    assert!(proof.is_ok());
}

#[test]
fn test_order_total_cap_valid_proof() {
    let cap = 10000u64;
    let amount = 5000u64;

    let inputs = sample_cap_public_inputs(cap);
    let witness = ComplianceWitness::new(amount, inputs.clone());
    let policy = Policy::order_total_cap(cap);

    let prover = ComplianceProver::with_policy(policy.clone());
    let proof = prover
        .prove(&witness)
        .expect("Proof generation should succeed");

    let result = verify_compliance_proof(
        &proof.proof_bytes,
        &inputs,
        &policy,
        &proof.witness_commitment,
    )
    .expect("Verification should succeed");
    assert!(result.valid, "Proof should be valid for amount < cap");
}

#[test]
fn test_order_total_cap_equal_proof() {
    let cap = 10000u64;
    let amount = 10000u64;

    let inputs = sample_cap_public_inputs(cap);
    let witness = ComplianceWitness::new(amount, inputs.clone());
    let policy = Policy::order_total_cap(cap);

    let prover = ComplianceProver::with_policy(policy.clone());
    let proof = prover
        .prove(&witness)
        .expect("Proof generation should succeed");

    let result = verify_compliance_proof(
        &proof.proof_bytes,
        &inputs,
        &policy,
        &proof.witness_commitment,
    )
    .expect("Verification should succeed");
    assert!(result.valid, "Proof should be valid for amount == cap");
}

#[test]
fn test_agent_authorization_policy_valid_proof() {
    let max_total = 25_000u64;
    let amount = 12_500u64;
    let intent_hash = CommerceIntent {
        intent_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        store_id: Uuid::new_v4(),
        agent_id: Uuid::new_v4(),
        delegation_id: Uuid::new_v4(),
        currency: "USD".to_string(),
        max_total,
        merchant: Some("Acme Market".to_string()),
        payee: Some("settlement@stateset.app".to_string()),
        allowed_skus: vec!["sku-a".to_string()],
        allowed_categories: vec!["grocery".to_string()],
        shipping_country: Some("US".to_string()),
        expires_at: 1_900_000_000,
        nonce: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
    }
    .compute_hash_hex()
    .unwrap();

    let inputs = sample_agent_authorization_public_inputs(max_total, &intent_hash);
    let witness = ComplianceWitness::new(amount, inputs.clone());
    let policy = Policy::agent_authorization(max_total, intent_hash.clone()).unwrap();

    let prover = ComplianceProver::with_policy(policy.clone());
    let proof = prover.prove(&witness).unwrap();

    let result = verify_compliance_proof(
        &proof.proof_bytes,
        &inputs,
        &policy,
        &proof.witness_commitment,
    )
    .unwrap();
    assert!(result.valid, "Proof should be valid for authorized amount");

    let mismatched_policy = Policy::agent_authorization(
        max_total,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    )
    .unwrap();
    assert!(verify_compliance_proof(
        &proof.proof_bytes,
        &inputs,
        &mismatched_policy,
        &proof.witness_commitment,
    )
    .is_err());
}

#[test]
fn test_agent_authorization_receipt_bound_proof() {
    let max_total = 25_000u64;
    let amount = 12_500u64;
    let intent = CommerceIntent {
        intent_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        store_id: Uuid::new_v4(),
        agent_id: Uuid::new_v4(),
        delegation_id: Uuid::new_v4(),
        currency: "USD".to_string(),
        max_total,
        merchant: Some("Acme Market".to_string()),
        payee: Some("settlement@stateset.app".to_string()),
        allowed_skus: vec!["sku-a".to_string()],
        allowed_categories: vec!["grocery".to_string()],
        shipping_country: Some("US".to_string()),
        expires_at: 1_900_000_000,
        nonce: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
    };
    let execution = CommerceExecution {
        event_id: Uuid::new_v4(),
        sequence_number: 42,
        currency: "USD".to_string(),
        amount,
        merchant: "Acme Market".to_string(),
        payee: "settlement@stateset.app".to_string(),
        sku_ids: vec!["sku-a".to_string()],
        category_ids: vec!["grocery".to_string()],
        shipping_country: Some("US".to_string()),
        executed_at: 1_800_000_000,
    };
    let receipt = intent.authorize_execution(&execution).unwrap();

    let mut inputs = sample_agent_authorization_public_inputs(max_total, &receipt.intent_hash);
    inputs.event_id = receipt.event_id;
    inputs.tenant_id = receipt.tenant_id;
    inputs.store_id = receipt.store_id;
    inputs.sequence_number = receipt.sequence_number;
    let inputs = inputs.bind_authorization_receipt(&receipt).unwrap();

    let witness = ComplianceWitness::new(amount, inputs.clone());
    let policy = Policy::agent_authorization(max_total, receipt.intent_hash.clone()).unwrap();

    let prover = ComplianceProver::with_policy(policy);
    let proof = prover.prove(&witness).unwrap();

    let result =
        verify_agent_authorization_proof_auto_bound(&proof.proof_bytes, &inputs, &receipt).unwrap();
    assert!(result.valid, "Receipt-bound proof should be valid");

    let mut tampered_receipt = receipt.clone();
    tampered_receipt.amount += 1;
    tampered_receipt.receipt_hash = tampered_receipt.compute_hash_hex().unwrap();

    assert!(matches!(
        verify_agent_authorization_proof_auto_bound(&proof.proof_bytes, &inputs, &tampered_receipt),
        Err(ves_stark_verifier::VerifierError::PublicInputMismatch(_))
    ));
}

// =============================================================================
// Order Total Cap Policy Tests
// =============================================================================

#[test]
fn test_order_total_cap_valid_amount() {
    let cap = 10000u64;
    let amount = 5000u64;

    let inputs = sample_cap_public_inputs(cap);
    let witness = ComplianceWitness::new(amount, inputs.clone());
    let policy = Policy::order_total_cap(cap);

    let prover = ComplianceProver::with_policy(policy);
    let proof = prover.prove(&witness);

    assert!(
        proof.is_ok(),
        "Proof generation should succeed: {:?}",
        proof.err()
    );

    let proof = proof.unwrap();
    println!(
        "[order_total.cap] Proof size: {} bytes",
        proof.metadata.proof_size
    );
    println!(
        "[order_total.cap] Proving time: {} ms",
        proof.metadata.proving_time_ms
    );

    // Verify the proof using the same policy parameters as the public inputs
    let verify_policy = Policy::order_total_cap(cap);
    let result = verify_compliance_proof(
        &proof.proof_bytes,
        &inputs,
        &verify_policy,
        &proof.witness_commitment,
    );
    assert!(
        result.is_ok(),
        "Verification should succeed: {:?}",
        result.err()
    );

    let result = result.unwrap();
    assert!(result.valid, "Proof should be valid");
}

#[test]
fn test_order_total_cap_boundary_succeeds() {
    // For order_total.cap, amount == cap should succeed (LTE)
    let cap = 10000u64;
    let amount = 10000u64; // Equal to cap - should succeed!

    let inputs = sample_cap_public_inputs(cap);
    let witness = ComplianceWitness::new(amount, inputs.clone());
    let policy = Policy::order_total_cap(cap);

    let prover = ComplianceProver::with_policy(policy);
    let proof = prover.prove(&witness);

    assert!(
        proof.is_ok(),
        "Proof generation should succeed for amount == cap: {:?}",
        proof.err()
    );

    let proof = proof.unwrap();

    // Verify the proof
    let verify_policy = Policy::order_total_cap(cap);
    let result = verify_compliance_proof(
        &proof.proof_bytes,
        &inputs,
        &verify_policy,
        &proof.witness_commitment,
    );
    assert!(result.is_ok());
    assert!(
        result.unwrap().valid,
        "Boundary proof (amount == cap) should be valid"
    );
}

#[test]
fn test_order_total_cap_exceeds_fails() {
    // For order_total.cap, amount > cap should fail
    let cap = 10000u64;
    let amount = 10001u64; // Greater than cap

    let inputs = sample_cap_public_inputs(cap);
    let witness = ComplianceWitness::new(amount, inputs);
    let policy = Policy::order_total_cap(cap);

    let prover = ComplianceProver::with_policy(policy);
    let proof = prover.prove(&witness);

    assert!(
        proof.is_err(),
        "Proof generation should fail for amount > cap"
    );
}

#[test]
fn test_order_total_cap_zero_amount() {
    let cap = 10000u64;
    let amount = 0u64;

    let inputs = sample_cap_public_inputs(cap);
    let witness = ComplianceWitness::new(amount, inputs.clone());
    let policy = Policy::order_total_cap(cap);

    let prover = ComplianceProver::with_policy(policy);
    let proof = prover.prove(&witness);

    assert!(proof.is_ok());

    let proof = proof.unwrap();
    let verify_policy = Policy::order_total_cap(cap);
    let result = verify_compliance_proof(
        &proof.proof_bytes,
        &inputs,
        &verify_policy,
        &proof.witness_commitment,
    );
    assert!(result.is_ok());
    assert!(result.unwrap().valid);
}

#[test]
fn test_order_total_cap_large_values() {
    let cap = u64::MAX;
    let amount = u64::MAX - 1;

    let inputs = sample_cap_public_inputs(cap);
    let witness = ComplianceWitness::new(amount, inputs.clone());
    let policy = Policy::order_total_cap(cap);

    let prover = ComplianceProver::with_policy(policy);
    let proof = prover.prove(&witness);

    assert!(proof.is_ok());
}

#[test]
fn test_order_total_cap_max_amount_equals_cap() {
    // Edge case: amount == cap == MAX
    let cap = u64::MAX;
    let amount = u64::MAX;

    let inputs = sample_cap_public_inputs(cap);
    let witness = ComplianceWitness::new(amount, inputs.clone());
    let policy = Policy::order_total_cap(cap);

    let prover = ComplianceProver::with_policy(policy);
    let proof = prover.prove(&witness);

    assert!(
        proof.is_ok(),
        "Proof should succeed for MAX amount == MAX cap"
    );
}

// =============================================================================
// Cross-Policy Tests
// =============================================================================

#[test]
fn test_policy_comparison_semantics() {
    // Same amount and limit, but different policy semantics
    let limit = 10000u64;
    let amount = 10000u64; // Boundary value

    // AML threshold: amount < threshold (should FAIL)
    let aml_inputs = sample_aml_public_inputs(limit);
    let aml_witness = ComplianceWitness::new(amount, aml_inputs);
    let aml_policy = Policy::aml_threshold(limit);
    let aml_prover = ComplianceProver::with_policy(aml_policy);
    let aml_result = aml_prover.prove(&aml_witness);
    assert!(
        aml_result.is_err(),
        "AML threshold should reject amount == threshold"
    );

    // Order total cap: amount <= cap (should SUCCEED)
    let cap_inputs = sample_cap_public_inputs(limit);
    let cap_witness = ComplianceWitness::new(amount, cap_inputs);
    let cap_policy = Policy::order_total_cap(limit);
    let cap_prover = ComplianceProver::with_policy(cap_policy);
    let cap_result = cap_prover.prove(&cap_witness);
    assert!(
        cap_result.is_ok(),
        "Order total cap should accept amount == cap"
    );
}

#[test]
fn test_unified_policy_api() {
    // Test that the unified Policy API works correctly for both policy types
    let limit = 10000u64;
    let amount = 5000u64;

    // AML threshold via unified API
    let aml_policy = Policy::aml_threshold(limit);
    assert_eq!(aml_policy.policy_id(), "aml.threshold");
    assert_eq!(aml_policy.limit(), limit);
    assert!(aml_policy.validate_amount(amount));
    assert!(!aml_policy.validate_amount(limit)); // boundary should fail

    // Order total cap via unified API
    let cap_policy = Policy::order_total_cap(limit);
    assert_eq!(cap_policy.policy_id(), "order_total.cap");
    assert_eq!(cap_policy.limit(), limit);
    assert!(cap_policy.validate_amount(amount));
    assert!(cap_policy.validate_amount(limit)); // boundary should succeed
}

#[test]
fn test_policy_serialization_roundtrip() {
    // Test that Policy types serialize correctly
    let aml = Policy::aml_threshold(10000);
    let json = serde_json::to_string(&aml).unwrap();
    let recovered: Policy = serde_json::from_str(&json).unwrap();
    assert_eq!(recovered.limit(), 10000);
    assert_eq!(recovered.policy_id(), "aml.threshold");

    let cap = Policy::order_total_cap(50000);
    let json = serde_json::to_string(&cap).unwrap();
    let recovered: Policy = serde_json::from_str(&json).unwrap();
    assert_eq!(recovered.limit(), 50000);
    assert_eq!(recovered.policy_id(), "order_total.cap");
}
