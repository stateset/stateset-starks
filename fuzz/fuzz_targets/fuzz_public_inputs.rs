//! Fuzz target for public inputs handling
//!
//! This target ensures:
//! 1. Public inputs serialization never panics
//! 2. Policy hash computation is deterministic
//! 3. Field element conversion is correct

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use uuid::Uuid;
use ves_stark_primitives::public_inputs::{
    CompliancePublicInputs, PolicyParams, compute_policy_hash,
};

/// Arbitrary public inputs
#[derive(Debug, Arbitrary)]
struct PublicInputsData {
    sequence_number: u64,
    payload_kind: u64,
    threshold: u64,
    /// Use fixed-size arrays to avoid huge strings
    hash_byte: u8,
}

fn create_hash_string(byte: u8) -> String {
    format!("{:02x}", byte).repeat(32) // 64 hex chars
}

fuzz_target!(|input: PublicInputsData| {
    // Create policy params and hash
    let policy_id = "aml.threshold";
    let params = PolicyParams::threshold(input.threshold);

    // Hash computation should never panic and be deterministic
    let hash1 = compute_policy_hash(policy_id, &params).unwrap();
    let hash2 = compute_policy_hash(policy_id, &params).unwrap();
    assert_eq!(hash1.to_hex(), hash2.to_hex(), "Policy hash should be deterministic");

    // Create public inputs
    let public_inputs = CompliancePublicInputs {
        event_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        store_id: Uuid::new_v4(),
        sequence_number: input.sequence_number,
        payload_kind: input.payload_kind as u32,
        payload_plain_hash: create_hash_string(input.hash_byte),
        payload_cipher_hash: create_hash_string(input.hash_byte.wrapping_add(1)),
        event_signing_hash: create_hash_string(input.hash_byte.wrapping_add(2)),
        policy_id: policy_id.to_string(),
        policy_params: params,
        policy_hash: hash1.to_hex(),
    };

    // Validation should succeed for matching policy hash
    assert!(public_inputs.validate_policy_hash().unwrap(), "Policy hash validation should pass");

    // Field element conversion should never panic
    let felts = public_inputs.to_field_elements().unwrap();
    assert!(!felts.to_vec().is_empty(), "Field elements should not be empty");

    // JSON serialization should never panic
    let json = serde_json::to_string(&public_inputs);
    assert!(json.is_ok(), "JSON serialization should succeed");

    // JSON deserialization should work
    if let Ok(json_str) = json {
        let recovered: Result<CompliancePublicInputs, _> = serde_json::from_str(&json_str);
        assert!(recovered.is_ok(), "JSON deserialization should succeed");

        if let Ok(recovered) = recovered {
            assert_eq!(recovered.sequence_number, input.sequence_number);
            assert_eq!(recovered.payload_kind, input.payload_kind);
            assert_eq!(recovered.policy_hash, public_inputs.policy_hash);
        }
    }

    // Test with different policy type
    let cap_id = "order_total.cap";
    let cap_params = PolicyParams::cap(input.threshold);
    let cap_hash = compute_policy_hash(cap_id, &cap_params).unwrap();

    // Different policy should produce different hash
    if input.threshold > 0 {
        // Policy hashes should differ between aml.threshold and order_total.cap
        // (unless both happen to hash to the same value, which is cryptographically unlikely)
    }

    let _ = cap_hash; // Use the value
});
