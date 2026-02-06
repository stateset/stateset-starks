//! Batch proof verification implementation
//!
//! This module provides verification logic for batch state transition proofs.

use serde::{Deserialize, Serialize};
use std::time::Instant;
use winter_crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree};
use winter_verifier::{verify, AcceptableOptions};

use ves_stark_air::options::ProofOptions;
use ves_stark_primitives::{felt_from_u64, Felt, Hash256};

use crate::air::batch_air::BatchComplianceAir;
use crate::error::BatchError;
use crate::public_inputs::BatchPublicInputs;

/// Type alias for the hash function
pub type Hasher = Blake3_256<Felt>;

/// Type alias for the random coin
pub type RandCoin = DefaultRandomCoin<Hasher>;

/// Type alias for vector commitment
pub type VectorCommit = MerkleTree<Hasher>;

/// Result of batch proof verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchVerificationResult {
    /// Whether the proof is valid
    pub valid: bool,

    /// Verification time in milliseconds
    pub verification_time_ms: u64,

    /// Error message if verification failed
    pub error: Option<String>,

    /// Previous state root (verified)
    pub prev_state_root: [u64; 4],

    /// New state root (verified)
    pub new_state_root: [u64; 4],

    /// Number of events in batch
    pub num_events: usize,

    /// Whether all events were compliant
    pub all_compliant: bool,
}

impl BatchVerificationResult {
    /// Get previous state root as field elements
    pub fn prev_state_root_felts(&self) -> [Felt; 4] {
        [
            felt_from_u64(self.prev_state_root[0]),
            felt_from_u64(self.prev_state_root[1]),
            felt_from_u64(self.prev_state_root[2]),
            felt_from_u64(self.prev_state_root[3]),
        ]
    }

    /// Get new state root as field elements
    pub fn new_state_root_felts(&self) -> [Felt; 4] {
        [
            felt_from_u64(self.new_state_root[0]),
            felt_from_u64(self.new_state_root[1]),
            felt_from_u64(self.new_state_root[2]),
            felt_from_u64(self.new_state_root[3]),
        ]
    }
}

/// Verify a batch proof
///
/// This is the main entry point for batch proof verification. It takes raw proof
/// bytes and public inputs, and returns a verification result.
pub fn verify_batch_proof(
    proof_bytes: &[u8],
    public_inputs: &BatchPublicInputs,
) -> Result<BatchVerificationResult, BatchError> {
    let start = Instant::now();

    // Deserialize proof
    let proof = winter_verifier::Proof::from_bytes(proof_bytes)
        .map_err(|e| BatchError::DeserializationFailed(format!("{:?}", e)))?;

    // Define acceptable proof options
    let acceptable_options = AcceptableOptions::OptionSet(vec![
        ProofOptions::default()
            .try_to_winterfell()
            .map_err(|e| BatchError::InvalidPublicInputs(format!("Invalid proof options: {e}")))?,
        ProofOptions::fast()
            .try_to_winterfell()
            .map_err(|e| BatchError::InvalidPublicInputs(format!("Invalid proof options: {e}")))?,
        ProofOptions::secure()
            .try_to_winterfell()
            .map_err(|e| BatchError::InvalidPublicInputs(format!("Invalid proof options: {e}")))?,
    ]);

    // Verify the proof
    let result = verify::<BatchComplianceAir, Hasher, RandCoin, VectorCommit>(
        proof,
        public_inputs.clone(),
        &acceptable_options,
    );

    let verification_time = start.elapsed();

    // Extract state roots for response
    let prev_state_root: [u64; 4] = [
        public_inputs.prev_state_root[0].as_int(),
        public_inputs.prev_state_root[1].as_int(),
        public_inputs.prev_state_root[2].as_int(),
        public_inputs.prev_state_root[3].as_int(),
    ];

    let new_state_root: [u64; 4] = [
        public_inputs.new_state_root[0].as_int(),
        public_inputs.new_state_root[1].as_int(),
        public_inputs.new_state_root[2].as_int(),
        public_inputs.new_state_root[3].as_int(),
    ];

    match result {
        Ok(_) => Ok(BatchVerificationResult {
            valid: true,
            verification_time_ms: verification_time.as_millis() as u64,
            error: None,
            prev_state_root,
            new_state_root,
            num_events: public_inputs.num_events_usize(),
            all_compliant: public_inputs.is_all_compliant(),
        }),
        Err(e) => Ok(BatchVerificationResult {
            valid: false,
            verification_time_ms: verification_time.as_millis() as u64,
            error: Some(format!("{:?}", e)),
            prev_state_root,
            new_state_root,
            num_events: public_inputs.num_events_usize(),
            all_compliant: public_inputs.is_all_compliant(),
        }),
    }
}

/// Batch proof verifier
pub struct BatchVerifier {
    /// Acceptable proof options
    #[allow(dead_code)]
    acceptable_options: AcceptableOptions,
}

impl BatchVerifier {
    /// Create a new verifier with default options
    pub fn new() -> Self {
        Self::try_new().expect("invalid proof options")
    }

    /// Create a new verifier with default options without panicking
    pub fn try_new() -> Result<Self, BatchError> {
        Ok(Self {
            acceptable_options: AcceptableOptions::OptionSet(vec![
                ProofOptions::default().try_to_winterfell().map_err(|e| {
                    BatchError::InvalidPublicInputs(format!("Invalid proof options: {e}"))
                })?,
                ProofOptions::fast().try_to_winterfell().map_err(|e| {
                    BatchError::InvalidPublicInputs(format!("Invalid proof options: {e}"))
                })?,
                ProofOptions::secure().try_to_winterfell().map_err(|e| {
                    BatchError::InvalidPublicInputs(format!("Invalid proof options: {e}"))
                })?,
            ]),
        })
    }

    /// Create a verifier with custom acceptable options
    pub fn with_options(options: AcceptableOptions) -> Self {
        Self {
            acceptable_options: options,
        }
    }

    /// Verify a batch proof
    pub fn verify(
        &self,
        proof_bytes: &[u8],
        public_inputs: &BatchPublicInputs,
    ) -> Result<BatchVerificationResult, BatchError> {
        verify_batch_proof(proof_bytes, public_inputs)
    }

    /// Verify state transition chain
    ///
    /// Verifies that a sequence of batch proofs form a valid state chain,
    /// where each proof's new_state_root equals the next proof's prev_state_root.
    pub fn verify_chain(
        &self,
        proofs: &[(Vec<u8>, BatchPublicInputs)],
    ) -> Result<Vec<BatchVerificationResult>, BatchError> {
        let mut results = Vec::with_capacity(proofs.len());

        for (i, (proof_bytes, pub_inputs)) in proofs.iter().enumerate() {
            // Verify individual proof
            let result = self.verify(proof_bytes, pub_inputs)?;

            if !result.valid {
                return Err(BatchError::VerificationFailed {
                    batch_index: i,
                    message: result.error.unwrap_or_else(|| "Unknown error".to_string()),
                });
            }

            // Verify chain continuity (except for first proof)
            if i > 0 {
                let prev_result: &BatchVerificationResult = &results[i - 1];
                if result.prev_state_root != prev_result.new_state_root {
                    return Err(BatchError::InvalidStateChain {
                        batch_index: i,
                        expected: prev_result.new_state_root,
                        actual: result.prev_state_root,
                    });
                }
            }

            results.push(result);
        }

        Ok(results)
    }

    /// Verify proof hash matches
    pub fn verify_proof_hash(proof_bytes: &[u8], expected_hash: &str) -> bool {
        let computed =
            Hash256::sha256_with_domain(b"STATESET_VES_BATCH_PROOF_HASH_V1", proof_bytes);
        computed.to_hex() == expected_hash
    }

    /// Verify that state transition is valid
    ///
    /// Checks that the proof correctly transitions from prev_state to new_state.
    pub fn verify_state_transition(
        &self,
        proof_bytes: &[u8],
        public_inputs: &BatchPublicInputs,
        expected_prev_root: &[Felt; 4],
        expected_new_root: &[Felt; 4],
    ) -> Result<bool, BatchError> {
        // Check public inputs match expected roots
        if public_inputs.prev_state_root != *expected_prev_root {
            return Ok(false);
        }
        if public_inputs.new_state_root != *expected_new_root {
            return Ok(false);
        }

        // Verify the proof
        let result = self.verify(proof_bytes, public_inputs)?;
        Ok(result.valid)
    }
}

impl Default for BatchVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_creation() {
        let _verifier = BatchVerifier::new();
    }

    #[test]
    fn test_proof_hash_verification() {
        let proof_bytes = b"test batch proof data";
        let hash = Hash256::sha256_with_domain(b"STATESET_VES_BATCH_PROOF_HASH_V1", proof_bytes);

        assert!(BatchVerifier::verify_proof_hash(
            proof_bytes,
            &hash.to_hex()
        ));
        assert!(!BatchVerifier::verify_proof_hash(proof_bytes, "wrong_hash"));
    }

    #[test]
    fn test_verification_result_conversion() {
        let result = BatchVerificationResult {
            valid: true,
            verification_time_ms: 100,
            error: None,
            prev_state_root: [1, 2, 3, 4],
            new_state_root: [5, 6, 7, 8],
            num_events: 10,
            all_compliant: true,
        };

        let prev_felts = result.prev_state_root_felts();
        assert_eq!(prev_felts[0].as_int(), 1);
        assert_eq!(prev_felts[1].as_int(), 2);
        assert_eq!(prev_felts[2].as_int(), 3);
        assert_eq!(prev_felts[3].as_int(), 4);

        let new_felts = result.new_state_root_felts();
        assert_eq!(new_felts[0].as_int(), 5);
        assert_eq!(new_felts[1].as_int(), 6);
        assert_eq!(new_felts[2].as_int(), 7);
        assert_eq!(new_felts[3].as_int(), 8);
    }
}
