//! Proof verification implementation
//!
//! This module provides the main verification logic for VES compliance proofs.

use crate::error::VerifierError;
use ves_stark_air::compliance::{ComplianceAir, PublicInputs};
use ves_stark_air::policies::aml_threshold::AmlThresholdPolicy;
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

    /// The threshold that was verified against
    pub threshold: u64,
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
    policy: &AmlThresholdPolicy,
    witness_commitment: &[u64; 4],
) -> Result<VerificationResult, VerifierError> {
    let start = Instant::now();

    // Validate public inputs
    if !public_inputs.validate_policy_hash() {
        return Err(VerifierError::InvalidPolicyHash {
            expected: CompliancePublicInputs::compute_policy_hash(
                &public_inputs.policy_id,
                &public_inputs.policy_params,
            ).to_hex(),
            actual: public_inputs.policy_hash.clone(),
        });
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
    let pub_inputs_felts = public_inputs.to_field_elements();
    let pub_inputs = PublicInputs::with_commitment(
        policy.threshold,
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
            threshold: policy.threshold,
        }),
        Err(e) => Ok(VerificationResult {
            valid: false,
            verification_time_ms: verification_time.as_millis() as u64,
            error: Some(format!("{:?}", e)),
            policy_id: public_inputs.policy_id.clone(),
            threshold: policy.threshold,
        }),
    }
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
        policy: &AmlThresholdPolicy,
        witness_commitment: &[u64; 4],
    ) -> Result<VerificationResult, VerifierError> {
        verify_compliance_proof(proof_bytes, public_inputs, policy, witness_commitment)
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
        let hash = CompliancePublicInputs::compute_policy_hash(policy_id, &params);

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

    #[test]
    fn test_verifier_creation() {
        let _verifier = ComplianceVerifier::new();
    }

    #[test]
    fn test_invalid_policy_hash() {
        let threshold = 10000u64;
        let mut inputs = sample_inputs(threshold);
        inputs.policy_hash = "invalid".repeat(8);

        let policy = AmlThresholdPolicy::new(threshold);
        let witness_commitment = [0u64; 4]; // dummy commitment for this test
        let result = verify_compliance_proof(&[], &inputs, &policy, &witness_commitment);

        assert!(matches!(result, Err(VerifierError::InvalidPolicyHash { .. })));
    }

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
}
