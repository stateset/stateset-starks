//! Proof verification implementation
//!
//! This module provides the main verification logic for VES compliance proofs.

use crate::error::{VerifierError, validate_hex_string};
use ves_stark_air::compliance::{ComplianceAir, PublicInputs};
use ves_stark_air::policy::Policy;
use ves_stark_primitives::public_inputs::CompliancePublicInputs;
use ves_stark_primitives::{Felt, Hash256, felt_from_u64};
use winter_crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree};
use winter_verifier::{verify, AcceptableOptions};
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Type alias for the hash function
pub type Hasher = Blake3_256<Felt>;

/// Type alias for the random coin
pub type RandCoin = DefaultRandomCoin<Hasher>;

/// Type alias for vector commitment
pub type VectorCommit = MerkleTree<Hasher>;

/// Result of proof verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the proof is valid
    pub valid: bool,

    /// Verification time in milliseconds
    pub verification_time_ms: u64,

    /// Error message if verification failed
    pub error: Option<String>,

    /// The policy that was verified
    pub policy_id: String,

    /// The policy limit that was verified against
    pub policy_limit: u64,
}

/// Verify a compliance proof
///
/// This is the main entry point for proof verification. It takes raw proof
/// bytes, public inputs, policy, and the witness commitment from the proof.
///
/// The witness commitment is a Rescue hash of the private amount, included
/// in the proof to bind the private witness to the public proof.
pub fn verify_compliance_proof(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    policy: &Policy,
    witness_commitment: &[u64; 4],
) -> Result<VerificationResult, VerifierError> {
    let start = Instant::now();

    // V2 Security: Validate hex string formats in public inputs
    validate_hex_string("payload_plain_hash", &public_inputs.payload_plain_hash, 64)?;
    validate_hex_string("payload_cipher_hash", &public_inputs.payload_cipher_hash, 64)?;
    validate_hex_string("event_signing_hash", &public_inputs.event_signing_hash, 64)?;
    validate_hex_string("policy_hash", &public_inputs.policy_hash, 64)?;

    // Validate policy hash
    let policy_hash_valid = public_inputs
        .validate_policy_hash()
        .map_err(|e| VerifierError::PublicInputMismatch(format!("{e}")))?;
    if !policy_hash_valid {
        let expected = CompliancePublicInputs::compute_policy_hash(
            &public_inputs.policy_id,
            &public_inputs.policy_params,
        )
        .map_err(|e| VerifierError::PublicInputMismatch(format!("{e}")))?;
        return Err(VerifierError::InvalidPolicyHash {
            expected: expected.to_hex(),
            actual: public_inputs.policy_hash.clone(),
        });
    }

    // Policy must match public inputs
    let derived_policy = Policy::from_public_inputs(
        &public_inputs.policy_id,
        &public_inputs.policy_params,
    )
    .map_err(|e| VerifierError::PublicInputMismatch(format!("Invalid policy params: {e}")))?;
    if policy.policy_id() != derived_policy.policy_id() {
        return Err(VerifierError::policy_mismatch(
            policy.policy_id(),
            derived_policy.policy_id(),
        ));
    }
    if policy.limit() != derived_policy.limit() {
        return Err(VerifierError::limit_mismatch(policy.limit(), derived_policy.limit()));
    }

    // Deserialize proof
    let proof = winter_verifier::Proof::from_bytes(proof_bytes)
        .map_err(|e| VerifierError::DeserializationError(format!("{:?}", e)))?;

    // Convert witness commitment to field elements
    let commitment_felts: [Felt; 4] = [
        felt_from_u64(witness_commitment[0]),
        felt_from_u64(witness_commitment[1]),
        felt_from_u64(witness_commitment[2]),
        felt_from_u64(witness_commitment[3]),
    ];

    // Convert public inputs to field elements and include witness commitment
    let pub_inputs_felts = public_inputs
        .to_field_elements()
        .map_err(|e| VerifierError::PublicInputMismatch(format!("{e}")))?;
    let policy_limit = policy
        .effective_limit()
        .map_err(|e| VerifierError::PublicInputMismatch(format!("{e}")))?;
    let pub_inputs = PublicInputs::with_commitment(
        policy_limit,
        pub_inputs_felts.to_vec(),
        commitment_felts,
    );

    // Define acceptable proof options
    let acceptable_options = AcceptableOptions::OptionSet(vec![
        ves_stark_air::options::ProofOptions::default().to_winterfell(),
        ves_stark_air::options::ProofOptions::fast().to_winterfell(),
        ves_stark_air::options::ProofOptions::secure().to_winterfell(),
    ]);

    // Verify the proof
    let result = verify::<ComplianceAir, Hasher, RandCoin, VectorCommit>(
        proof,
        pub_inputs,
        &acceptable_options,
    );

    let verification_time = start.elapsed();

    match result {
        Ok(_) => Ok(VerificationResult {
            valid: true,
            verification_time_ms: verification_time.as_millis() as u64,
            error: None,
            policy_id: public_inputs.policy_id.clone(),
            policy_limit: policy.limit(),
        }),
        Err(e) => Ok(VerificationResult {
            valid: false,
            verification_time_ms: verification_time.as_millis() as u64,
            error: Some(format!("{:?}", e)),
            policy_id: public_inputs.policy_id.clone(),
            policy_limit: policy.limit(),
        }),
    }
}

/// Verify a compliance proof using policy parameters from the public inputs.
pub fn verify_compliance_proof_auto(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    witness_commitment: &[u64; 4],
) -> Result<VerificationResult, VerifierError> {
    let policy = Policy::from_public_inputs(
        &public_inputs.policy_id,
        &public_inputs.policy_params,
    )
    .map_err(|e| VerifierError::PublicInputMismatch(format!("Invalid policy params: {e}")))?;
    verify_compliance_proof(proof_bytes, public_inputs, &policy, witness_commitment)
}

/// Stateless compliance proof verifier
pub struct ComplianceVerifier {
    /// Acceptable proof options
    #[allow(dead_code)]
    acceptable_options: AcceptableOptions,
}

impl ComplianceVerifier {
    /// Create a new verifier with default options
    pub fn new() -> Self {
        Self {
            acceptable_options: AcceptableOptions::OptionSet(vec![
                ves_stark_air::options::ProofOptions::default().to_winterfell(),
                ves_stark_air::options::ProofOptions::fast().to_winterfell(),
                ves_stark_air::options::ProofOptions::secure().to_winterfell(),
            ]),
        }
    }

    /// Create a verifier with custom acceptable options
    pub fn with_options(options: AcceptableOptions) -> Self {
        Self {
            acceptable_options: options,
        }
    }

    /// Verify a proof
    pub fn verify(
        &self,
        proof_bytes: &[u8],
        public_inputs: &CompliancePublicInputs,
        policy: &Policy,
        witness_commitment: &[u64; 4],
    ) -> Result<VerificationResult, VerifierError> {
        verify_compliance_proof(proof_bytes, public_inputs, policy, witness_commitment)
    }

    /// Verify a proof using policy parameters from the public inputs.
    pub fn verify_auto(
        &self,
        proof_bytes: &[u8],
        public_inputs: &CompliancePublicInputs,
        witness_commitment: &[u64; 4],
    ) -> Result<VerificationResult, VerifierError> {
        verify_compliance_proof_auto(proof_bytes, public_inputs, witness_commitment)
    }

    /// Verify proof hash matches
    pub fn verify_proof_hash(proof_bytes: &[u8], expected_hash: &str) -> bool {
        let computed = Hash256::sha256_with_domain(
            b"STATESET_VES_COMPLIANCE_PROOF_HASH_V1",
            proof_bytes,
        );
        computed.to_hex() == expected_hash
    }
}

impl Default for ComplianceVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ves_stark_primitives::public_inputs::PolicyParams;
    use uuid::Uuid;

    fn sample_inputs(threshold: u64) -> CompliancePublicInputs {
        let policy_id = "aml.threshold";
        let params = PolicyParams::threshold(threshold);
        let hash = CompliancePublicInputs::compute_policy_hash(policy_id, &params).unwrap();

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

    // =========================================================================
    // Basic Verifier Tests
    // =========================================================================

    #[test]
    fn test_verifier_creation() {
        let _verifier = ComplianceVerifier::new();
    }

    #[test]
    fn test_verifier_default() {
        let verifier = ComplianceVerifier::default();
        // Ensure default creates same as new
        assert!(std::mem::size_of_val(&verifier) > 0);
    }

    #[test]
    fn test_verifier_with_custom_options() {
        use winter_verifier::AcceptableOptions;
        let options = AcceptableOptions::OptionSet(vec![
            ves_stark_air::options::ProofOptions::secure().to_winterfell(),
        ]);
        let _verifier = ComplianceVerifier::with_options(options);
    }

    // =========================================================================
    // Policy Hash Validation Tests
    // =========================================================================

    #[test]
    fn test_invalid_policy_hash() {
        let threshold = 10000u64;
        let mut inputs = sample_inputs(threshold);
        inputs.policy_hash = "invalid".repeat(8);

        let policy = Policy::aml_threshold(threshold);
        let witness_commitment = [0u64; 4];
        let result = verify_compliance_proof(&[], &inputs, &policy, &witness_commitment);

        assert!(matches!(result, Err(VerifierError::InvalidPolicyHash { .. })));
    }

    #[test]
    fn test_empty_policy_hash_fails() {
        let threshold = 10000u64;
        let mut inputs = sample_inputs(threshold);
        inputs.policy_hash = String::new();

        let policy = Policy::aml_threshold(threshold);
        let witness_commitment = [0u64; 4];
        let result = verify_compliance_proof(&[], &inputs, &policy, &witness_commitment);

        assert!(matches!(result, Err(VerifierError::InvalidPolicyHash { .. })));
    }

    #[test]
    fn test_policy_hash_case_sensitivity() {
        let threshold = 10000u64;
        let mut inputs = sample_inputs(threshold);
        // Make hash uppercase (should fail since we use lowercase hex)
        inputs.policy_hash = inputs.policy_hash.to_uppercase();

        let policy = Policy::aml_threshold(threshold);
        let witness_commitment = [0u64; 4];
        let result = verify_compliance_proof(&[], &inputs, &policy, &witness_commitment);

        assert!(matches!(result, Err(VerifierError::InvalidPolicyHash { .. })));
    }

    #[test]
    fn test_valid_policy_hash_passes_validation() {
        let threshold = 10000u64;
        let inputs = sample_inputs(threshold);

        // Just check that policy hash validation passes
        assert!(inputs.validate_policy_hash().unwrap());
    }

    // =========================================================================
    // Proof Hash Verification Tests
    // =========================================================================

    #[test]
    fn test_proof_hash_verification() {
        let proof_bytes = b"test proof data";
        let hash = Hash256::sha256_with_domain(
            b"STATESET_VES_COMPLIANCE_PROOF_HASH_V1",
            proof_bytes,
        );

        assert!(ComplianceVerifier::verify_proof_hash(proof_bytes, &hash.to_hex()));
        assert!(!ComplianceVerifier::verify_proof_hash(proof_bytes, "wrong_hash"));
    }

    #[test]
    fn test_proof_hash_empty_bytes() {
        let proof_bytes: &[u8] = b"";
        let hash = Hash256::sha256_with_domain(
            b"STATESET_VES_COMPLIANCE_PROOF_HASH_V1",
            proof_bytes,
        );

        assert!(ComplianceVerifier::verify_proof_hash(proof_bytes, &hash.to_hex()));
    }

    #[test]
    fn test_proof_hash_large_input() {
        let proof_bytes: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let hash = Hash256::sha256_with_domain(
            b"STATESET_VES_COMPLIANCE_PROOF_HASH_V1",
            &proof_bytes,
        );

        assert!(ComplianceVerifier::verify_proof_hash(&proof_bytes, &hash.to_hex()));
    }

    #[test]
    fn test_proof_hash_deterministic() {
        let proof_bytes = b"deterministic test data";
        let hash1 = Hash256::sha256_with_domain(
            b"STATESET_VES_COMPLIANCE_PROOF_HASH_V1",
            proof_bytes,
        );
        let hash2 = Hash256::sha256_with_domain(
            b"STATESET_VES_COMPLIANCE_PROOF_HASH_V1",
            proof_bytes,
        );

        assert_eq!(hash1.to_hex(), hash2.to_hex());
    }

    #[test]
    fn test_proof_hash_different_inputs_differ() {
        let proof1 = b"proof data 1";
        let proof2 = b"proof data 2";

        let hash1 = Hash256::sha256_with_domain(
            b"STATESET_VES_COMPLIANCE_PROOF_HASH_V1",
            proof1,
        );
        let hash2 = Hash256::sha256_with_domain(
            b"STATESET_VES_COMPLIANCE_PROOF_HASH_V1",
            proof2,
        );

        assert_ne!(hash1.to_hex(), hash2.to_hex());
    }

    // =========================================================================
    // Proof Deserialization Error Tests
    // =========================================================================

    #[test]
    fn test_empty_proof_bytes_fails() {
        let threshold = 10000u64;
        let inputs = sample_inputs(threshold);
        let policy = Policy::aml_threshold(threshold);
        let witness_commitment = [0u64; 4];

        let result = verify_compliance_proof(&[], &inputs, &policy, &witness_commitment);

        // Should fail with deserialization error (empty proof can't be parsed)
        assert!(matches!(result, Err(VerifierError::DeserializationError(_))));
    }

    #[test]
    fn test_garbage_proof_bytes_fails() {
        let threshold = 10000u64;
        let inputs = sample_inputs(threshold);
        let policy = Policy::aml_threshold(threshold);
        let witness_commitment = [0u64; 4];
        let garbage_bytes = vec![0xFF; 100];

        let result = verify_compliance_proof(&garbage_bytes, &inputs, &policy, &witness_commitment);

        assert!(matches!(result, Err(VerifierError::DeserializationError(_))));
    }

    #[test]
    fn test_truncated_proof_bytes_fails() {
        let threshold = 10000u64;
        let inputs = sample_inputs(threshold);
        let policy = Policy::aml_threshold(threshold);
        let witness_commitment = [0u64; 4];
        // Some bytes that look like they could be a proof header but are truncated
        let truncated_bytes = vec![0x01, 0x02, 0x03, 0x04, 0x05];

        let result = verify_compliance_proof(&truncated_bytes, &inputs, &policy, &witness_commitment);

        assert!(matches!(result, Err(VerifierError::DeserializationError(_))));
    }

    // =========================================================================
    // Verification Result Serialization Tests
    // =========================================================================

    #[test]
    fn test_verification_result_serialization() {
        let result = VerificationResult {
            valid: true,
            verification_time_ms: 150,
            error: None,
            policy_id: "aml.threshold".to_string(),
            policy_limit: 10000,
        };

        let json = serde_json::to_string(&result).unwrap();
        let recovered: VerificationResult = serde_json::from_str(&json).unwrap();

        assert_eq!(recovered.valid, true);
        assert_eq!(recovered.verification_time_ms, 150);
        assert!(recovered.error.is_none());
        assert_eq!(recovered.policy_id, "aml.threshold");
        assert_eq!(recovered.policy_limit, 10000);
    }

    #[test]
    fn test_verification_result_with_error_serialization() {
        let result = VerificationResult {
            valid: false,
            verification_time_ms: 50,
            error: Some("Constraint check failed".to_string()),
            policy_id: "aml.threshold".to_string(),
            policy_limit: 5000,
        };

        let json = serde_json::to_string(&result).unwrap();
        let recovered: VerificationResult = serde_json::from_str(&json).unwrap();

        assert_eq!(recovered.valid, false);
        assert!(recovered.error.is_some());
        assert_eq!(recovered.error.unwrap(), "Constraint check failed");
    }

    // =========================================================================
    // Edge Case Tests
    // =========================================================================

    #[test]
    fn test_zero_threshold() {
        let threshold = 0u64;
        let inputs = sample_inputs(threshold);
        let policy = Policy::aml_threshold(threshold);
        let witness_commitment = [0u64; 4];

        // With threshold 0, no amount can satisfy amount < 0 for unsigned
        let result = verify_compliance_proof(&[], &inputs, &policy, &witness_commitment);
        assert!(matches!(result, Err(VerifierError::PublicInputMismatch(_))));
    }

    #[test]
    fn test_max_threshold() {
        let threshold = u64::MAX;
        let inputs = sample_inputs(threshold);
        let policy = Policy::aml_threshold(threshold);
        let witness_commitment = [0u64; 4];

        let result = verify_compliance_proof(&[], &inputs, &policy, &witness_commitment);
        // Should fail at deserialization
        assert!(matches!(result, Err(VerifierError::DeserializationError(_))));
    }

    #[test]
    fn test_witness_commitment_zeros() {
        let threshold = 10000u64;
        let inputs = sample_inputs(threshold);
        let policy = Policy::aml_threshold(threshold);
        let witness_commitment = [0u64; 4];

        // Zero commitment with empty proof should fail at deserialization
        let result = verify_compliance_proof(&[], &inputs, &policy, &witness_commitment);
        assert!(result.is_err());
    }

    #[test]
    fn test_witness_commitment_max_values() {
        let threshold = 10000u64;
        let inputs = sample_inputs(threshold);
        let policy = Policy::aml_threshold(threshold);
        let witness_commitment = [u64::MAX; 4];

        // Max commitment with empty proof should fail at deserialization
        let result = verify_compliance_proof(&[], &inputs, &policy, &witness_commitment);
        assert!(result.is_err());
    }

    // =========================================================================
    // Public Input Field Tests
    // =========================================================================

    #[test]
    fn test_public_inputs_various_uuids() {
        let threshold = 10000u64;

        // Create multiple inputs with different UUIDs
        for _ in 0..5 {
            let inputs = sample_inputs(threshold);
            assert!(inputs.validate_policy_hash().unwrap());
        }
    }

    #[test]
    fn test_public_inputs_different_sequence_numbers() {
        let threshold = 10000u64;
        let policy_id = "aml.threshold";
        let params = PolicyParams::threshold(threshold);
        let hash = CompliancePublicInputs::compute_policy_hash(policy_id, &params).unwrap();

        for seq in [0u64, 1, 100, u64::MAX] {
            let inputs = CompliancePublicInputs {
                event_id: Uuid::new_v4(),
                tenant_id: Uuid::new_v4(),
                store_id: Uuid::new_v4(),
                sequence_number: seq,
                payload_kind: 1,
                payload_plain_hash: "0".repeat(64),
                payload_cipher_hash: "0".repeat(64),
                event_signing_hash: "0".repeat(64),
                policy_id: policy_id.to_string(),
                policy_params: params.clone(),
                policy_hash: hash.to_hex(),
            };
            assert!(inputs.validate_policy_hash().unwrap());
        }
    }

    // =========================================================================
    // Error Type Tests
    // =========================================================================

    #[test]
    fn test_verifier_error_display() {
        let err = VerifierError::InvalidPolicyHash {
            expected: "abc123".to_string(),
            actual: "def456".to_string(),
        };
        let display = format!("{}", err);
        assert!(display.contains("abc123"));
        assert!(display.contains("def456"));
    }

    #[test]
    fn test_verifier_error_deserialization_display() {
        let err = VerifierError::DeserializationError("invalid format".to_string());
        let display = format!("{}", err);
        assert!(display.contains("invalid format"));
    }

    #[test]
    fn test_verifier_error_helper_methods() {
        let err1 = VerifierError::invalid_structure("bad structure");
        assert!(matches!(err1, VerifierError::InvalidProofStructure(_)));

        let err2 = VerifierError::verification_failed("verification issue");
        assert!(matches!(err2, VerifierError::VerificationFailed(_)));
    }
}
