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

/// Maximum allowed proof size in bytes (10 MB)
pub const MAX_BATCH_PROOF_SIZE: usize = 10 * 1024 * 1024;

/// Verify a batch proof
///
/// This is the main entry point for batch proof verification. It takes raw proof
/// bytes and public inputs, and returns a verification result.
pub fn verify_batch_proof(
    proof_bytes: &[u8],
    public_inputs: &BatchPublicInputs,
) -> Result<BatchVerificationResult, BatchError> {
    let start = Instant::now();

    // Size check: reject oversized proofs before attempting deserialization
    if proof_bytes.len() > MAX_BATCH_PROOF_SIZE {
        return Err(BatchError::ProofTooLarge {
            size: proof_bytes.len(),
            max_size: MAX_BATCH_PROOF_SIZE,
        });
    }

    let num_events = public_inputs.validate()?;

    // Deserialize proof
    let proof = winter_verifier::Proof::from_bytes(proof_bytes)
        .map_err(|e| BatchError::DeserializationFailed(format!("{e}")))?;

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
            num_events,
            all_compliant: public_inputs.is_all_compliant(),
        }),
        Err(e) => Ok(BatchVerificationResult {
            valid: false,
            verification_time_ms: verification_time.as_millis() as u64,
            error: Some(format!("{e}")),
            prev_state_root,
            new_state_root,
            num_events,
            all_compliant: public_inputs.is_all_compliant(),
        }),
    }
}

/// Batch proof verifier
pub struct BatchVerifier {
    _private: (),
}

impl BatchVerifier {
    /// Create a new verifier with default options
    pub fn new() -> Self {
        Self { _private: () }
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
                let prev_inputs = &proofs[i - 1].1;
                Self::validate_sequence_continuity(prev_inputs, pub_inputs, i)?;

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

    fn validate_sequence_continuity(
        prev_inputs: &BatchPublicInputs,
        curr_inputs: &BatchPublicInputs,
        batch_index: usize,
    ) -> Result<(), BatchError> {
        let expected_sequence_start = prev_inputs
            .sequence_end
            .as_int()
            .checked_add(1)
            .ok_or_else(|| {
                BatchError::InvalidPublicInputs(
                    "sequence range overflows u64 while checking chain continuity".to_string(),
                )
            })?;

        let current_sequence_start = curr_inputs.sequence_start.as_int();
        if current_sequence_start != expected_sequence_start {
            return Err(BatchError::InvalidPublicInputs(format!(
                "Invalid batch sequence continuity at batch {}: expected sequence_start {}, got {}",
                batch_index, expected_sequence_start, current_sequence_start
            )));
        }

        Ok(())
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
    use crate::public_inputs::BatchPolicyKind;

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

    #[test]
    fn test_sequence_continuity_check() {
        let mut prev_inputs = BatchPublicInputs {
            sequence_start: felt_from_u64(10),
            sequence_end: felt_from_u64(19),
            ..Default::default()
        };

        let next_inputs = BatchPublicInputs {
            sequence_start: felt_from_u64(20),
            sequence_end: felt_from_u64(29),
            ..Default::default()
        };

        assert!(BatchVerifier::validate_sequence_continuity(&prev_inputs, &next_inputs, 1).is_ok());

        prev_inputs.sequence_end = felt_from_u64(u64::MAX);
        let overflow_err =
            BatchVerifier::validate_sequence_continuity(&prev_inputs, &next_inputs, 1)
                .expect_err("overflow should be reported");
        assert!(matches!(overflow_err, BatchError::InvalidPublicInputs(_)));
    }

    #[test]
    fn test_sequence_continuity_check_with_gap() {
        let prev_inputs = BatchPublicInputs {
            sequence_start: felt_from_u64(10),
            sequence_end: felt_from_u64(19),
            ..Default::default()
        };

        let next_inputs = BatchPublicInputs {
            sequence_start: felt_from_u64(22),
            sequence_end: felt_from_u64(30),
            ..Default::default()
        };

        let err = BatchVerifier::validate_sequence_continuity(&prev_inputs, &next_inputs, 1)
            .expect_err("sequence gap should fail");
        assert!(matches!(err, BatchError::InvalidPublicInputs(_)));
    }

    #[test]
    fn test_verify_batch_proof_rejects_invalid_policy_kind_before_deserializing_proof() {
        let mut public_inputs = BatchPublicInputs::new(
            [felt_from_u64(1); 4],
            [felt_from_u64(2); 4],
            [felt_from_u64(3); 4],
            [felt_from_u64(4); 4],
            [felt_from_u64(5); 4],
            0,
            0,
            123,
            1,
            true,
            BatchPolicyKind::AmlThreshold,
            10_000,
            [felt_from_u64(9); 8],
        );
        public_inputs.policy_kind = felt_from_u64(99);

        let err = verify_batch_proof(b"not-a-proof", &public_inputs)
            .expect_err("invalid policy kind should be rejected before proof parsing");
        assert!(matches!(err, BatchError::InvalidPublicInputs(_)));
    }
}
