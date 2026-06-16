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

fn default_acceptable_options() -> Result<AcceptableOptions, BatchError> {
    Ok(AcceptableOptions::OptionSet(vec![
        ProofOptions::default()
            .try_to_winterfell()
            .map_err(|e| BatchError::InvalidPublicInputs(format!("Invalid proof options: {e}")))?,
        ProofOptions::secure()
            .try_to_winterfell()
            .map_err(|e| BatchError::InvalidPublicInputs(format!("Invalid proof options: {e}")))?,
    ]))
}

fn verify_batch_proof_with_options(
    proof_bytes: &[u8],
    public_inputs: &BatchPublicInputs,
    acceptable_options: &AcceptableOptions,
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

    // Verify the proof
    let result = verify::<BatchComplianceAir, Hasher, RandCoin, VectorCommit>(
        proof,
        public_inputs.clone(),
        acceptable_options,
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

/// Verify a batch proof
///
/// This is the main entry point for batch proof verification. It takes raw proof
/// bytes and public inputs, and returns a verification result.
pub fn verify_batch_proof(
    proof_bytes: &[u8],
    public_inputs: &BatchPublicInputs,
) -> Result<BatchVerificationResult, BatchError> {
    let acceptable_options = default_acceptable_options()?;
    verify_batch_proof_with_options(proof_bytes, public_inputs, &acceptable_options)
}

/// Batch proof verifier
pub struct BatchVerifier {
    acceptable_options: AcceptableOptions,
}

impl BatchVerifier {
    /// Create a new verifier with default options
    pub fn new() -> Self {
        Self::try_new().expect("built-in batch verifier proof options must remain valid")
    }

    /// Create a new verifier with default options without panicking.
    pub fn try_new() -> Result<Self, BatchError> {
        Ok(Self {
            acceptable_options: default_acceptable_options()?,
        })
    }

    /// Create a verifier with custom acceptable options.
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
        verify_batch_proof_with_options(proof_bytes, public_inputs, &self.acceptable_options)
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
        // A valid chain must stay within a single tenant and store. Without this
        // check, batches from unrelated tenants/stores could be stitched together
        // purely by coincidental sequence numbers and state-root linkage.
        if prev_inputs.tenant_id != curr_inputs.tenant_id {
            return Err(BatchError::InvalidPublicInputs(format!(
                "Tenant mismatch in chain at batch {}: chained batches must share one tenant",
                batch_index
            )));
        }
        if prev_inputs.store_id != curr_inputs.store_id {
            return Err(BatchError::InvalidPublicInputs(format!(
                "Store mismatch in chain at batch {}: chained batches must share one store",
                batch_index
            )));
        }

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
    use crate::air::trace_layout::MAX_BATCH_SIZE;
    use crate::prover::{BatchProver, BatchProverConfig, BatchWitnessBuilder};
    use crate::public_inputs::BatchPolicyKind;
    use crate::state::{BatchMetadata, BatchStateRoot};
    use uuid::Uuid;
    use ves_stark_primitives::hash_to_felts;
    use ves_stark_primitives::public_inputs::{
        compute_policy_hash, witness_commitment_u64_to_hex, CompliancePublicInputs, PolicyParams,
    };
    use ves_stark_primitives::{felt_from_u64, rescue::rescue_hash, FELT_ONE};
    use winter_verifier::AcceptableOptions;

    #[test]
    fn test_verifier_creation() {
        let _verifier = BatchVerifier::new();
    }

    fn sample_public_inputs(
        threshold: u64,
        amount: u64,
        sequence_number: u64,
        tenant_id: Uuid,
        store_id: Uuid,
    ) -> CompliancePublicInputs {
        let policy_id = "aml.threshold";
        let params = PolicyParams::threshold(threshold);
        let hash = compute_policy_hash(policy_id, &params).unwrap();
        let amount_limbs = [
            felt_from_u64(amount & 0xFFFFFFFF),
            felt_from_u64(amount >> 32),
            felt_from_u64(0),
            felt_from_u64(0),
            felt_from_u64(0),
            felt_from_u64(0),
            felt_from_u64(0),
            felt_from_u64(0),
        ];
        let commitment = rescue_hash(&amount_limbs);

        CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id,
            store_id,
            sequence_number,
            payload_kind: 1,
            payload_plain_hash: "0".repeat(64),
            payload_cipher_hash: "0".repeat(64),
            event_signing_hash: "0".repeat(64),
            policy_id: policy_id.to_string(),
            policy_params: params,
            policy_hash: hash.to_hex(),
            witness_commitment: Some(witness_commitment_u64_to_hex(&[
                commitment[0].as_int(),
                commitment[1].as_int(),
                commitment[2].as_int(),
                commitment[3].as_int(),
            ])),
            authorization_receipt_hash: None,
            amount_binding_hash: None,
        }
    }

    fn sample_policy_hash(threshold: u64) -> [Felt; 8] {
        let policy_id = "aml.threshold";
        let params = PolicyParams::threshold(threshold);
        let hash = compute_policy_hash(policy_id, &params).unwrap();
        hash_to_felts(&hash)
    }

    /// Build a real single-event `fast` batch proof, returning the full proof
    /// object alongside its public inputs.
    fn sample_fast_batch_proof_full() -> (crate::BatchProof, BatchPublicInputs) {
        let threshold = 10_000u64;
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();
        let metadata = BatchMetadata::with_ids(Uuid::new_v4(), tenant_id, store_id, 0, 0);

        let witness = BatchWitnessBuilder::new()
            .metadata(metadata)
            .policy_hash(sample_policy_hash(threshold))
            .policy_limit(threshold)
            .add_event(
                5_000,
                sample_public_inputs(threshold, 5_000, 0, tenant_id, store_id),
            )
            .unwrap()
            .build()
            .unwrap();

        let prover = BatchProver::with_config(
            BatchProverConfig::default().with_options(ProofOptions::fast()),
        );
        let proof = prover.prove(&witness).unwrap();
        let public_inputs = BatchPublicInputs::new(
            witness.prev_state_root.root,
            witness.compute_new_state_root().unwrap().root,
            witness.batch_id_felts(),
            witness.tenant_id_felts(),
            witness.store_id_felts(),
            witness.metadata.sequence_start,
            witness.metadata.sequence_end,
            witness.metadata.timestamp,
            witness.num_events(),
            witness.all_compliant(),
            BatchPolicyKind::AmlThreshold,
            witness.policy_limit,
            witness.public_inputs_accumulator().unwrap(),
        );

        (proof, public_inputs)
    }

    fn sample_fast_batch_proof() -> (Vec<u8>, BatchPublicInputs) {
        let (proof, public_inputs) = sample_fast_batch_proof_full();
        (proof.proof_bytes, public_inputs)
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
    fn test_default_batch_verifier_rejects_fast_proof() {
        let (proof_bytes, public_inputs) = sample_fast_batch_proof();

        let result = verify_batch_proof(&proof_bytes, &public_inputs).unwrap();
        assert!(!result.valid);

        let verifier = BatchVerifier::new();
        let result = verifier.verify(&proof_bytes, &public_inputs).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn test_batch_verifier_with_custom_options_accepts_fast_proof() {
        let (proof_bytes, public_inputs) = sample_fast_batch_proof();

        let verifier =
            BatchVerifier::with_options(AcceptableOptions::OptionSet(vec![ProofOptions::fast()
                .try_to_winterfell()
                .unwrap()]));
        let result = verifier.verify(&proof_bytes, &public_inputs).unwrap();
        assert!(result.valid, "{:?}", result.error);
    }

    /// A verifier that accepts the `fast` proof options used by the test helper.
    fn fast_verifier() -> BatchVerifier {
        BatchVerifier::with_options(AcceptableOptions::OptionSet(vec![ProofOptions::fast()
            .try_to_winterfell()
            .unwrap()]))
    }

    /// True if verification did NOT succeed (either an error or `valid == false`).
    fn rejected(result: Result<BatchVerificationResult, BatchError>) -> bool {
        result.map(|r| !r.valid).unwrap_or(true)
    }

    #[test]
    fn test_batch_verifier_rejects_tampered_public_inputs() {
        // A valid batch proof binds its public inputs. Lying about any bound field
        // while presenting the original proof must fail verification — this is the
        // core soundness property of the batch STARK and the basis for trusting
        // the state roots that get anchored on-chain.
        let (proof_bytes, valid_inputs) = sample_fast_batch_proof();
        let verifier = fast_verifier();

        // Sanity: the untampered pair verifies.
        assert!(verifier.verify(&proof_bytes, &valid_inputs).unwrap().valid);

        // Forged new state root (the value anchored on-chain).
        let mut pi = valid_inputs.clone();
        pi.new_state_root[0] += FELT_ONE;
        assert!(
            rejected(verifier.verify(&proof_bytes, &pi)),
            "tampered new_state_root accepted"
        );

        // Forged previous state root (breaks chain linkage).
        let mut pi = valid_inputs.clone();
        pi.prev_state_root[0] += FELT_ONE;
        assert!(
            rejected(verifier.verify(&proof_bytes, &pi)),
            "tampered prev_state_root accepted"
        );

        // Flipped all-compliant flag (claiming a non-compliant batch is clean, or vice versa).
        let mut pi = valid_inputs.clone();
        pi.all_compliant = FELT_ONE - pi.all_compliant;
        assert!(
            rejected(verifier.verify(&proof_bytes, &pi)),
            "flipped all_compliant accepted"
        );

        // Forged policy limit.
        let mut pi = valid_inputs.clone();
        pi.policy_limit += FELT_ONE;
        assert!(
            rejected(verifier.verify(&proof_bytes, &pi)),
            "tampered policy_limit accepted"
        );

        // Forged batch identity.
        let mut pi = valid_inputs.clone();
        pi.batch_id[0] += FELT_ONE;
        assert!(
            rejected(verifier.verify(&proof_bytes, &pi)),
            "tampered batch_id accepted"
        );

        // Forged public-inputs accumulator (the per-event binding digest).
        let mut pi = valid_inputs.clone();
        pi.public_inputs_accumulator[0] += FELT_ONE;
        assert!(
            rejected(verifier.verify(&proof_bytes, &pi)),
            "tampered accumulator accepted"
        );
    }

    #[test]
    fn test_batch_verifier_rejects_bit_flipped_proof() {
        let (mut proof_bytes, public_inputs) = sample_fast_batch_proof();
        let verifier = fast_verifier();
        assert!(verifier.verify(&proof_bytes, &public_inputs).unwrap().valid);

        // Flip a single bit in the middle of the proof; it must no longer verify.
        let mid = proof_bytes.len() / 2;
        proof_bytes[mid] ^= 0x01;
        assert!(
            rejected(verifier.verify(&proof_bytes, &public_inputs)),
            "bit-flipped batch proof accepted"
        );
    }

    /// Build a single-event batch proof chained onto `prev_root` at `sequence`,
    /// returning the proof bytes, its public inputs, and the resulting new state root.
    fn build_chained_batch(
        prev_root: BatchStateRoot,
        sequence: u64,
        tenant_id: Uuid,
        store_id: Uuid,
    ) -> (Vec<u8>, BatchPublicInputs, BatchStateRoot) {
        let threshold = 10_000u64;
        let metadata =
            BatchMetadata::with_ids(Uuid::new_v4(), tenant_id, store_id, sequence, sequence);
        let witness = BatchWitnessBuilder::new()
            .metadata(metadata)
            .policy_hash(sample_policy_hash(threshold))
            .policy_limit(threshold)
            .prev_state_root(prev_root)
            .add_event(
                5_000,
                sample_public_inputs(threshold, 5_000, sequence, tenant_id, store_id),
            )
            .unwrap()
            .build()
            .unwrap();

        let prover = BatchProver::with_config(
            BatchProverConfig::default().with_options(ProofOptions::fast()),
        );
        let proof = prover.prove(&witness).unwrap();
        let new_root = witness.compute_new_state_root().unwrap();
        let public_inputs = BatchPublicInputs::new(
            witness.prev_state_root.root,
            new_root.root,
            witness.batch_id_felts(),
            witness.tenant_id_felts(),
            witness.store_id_felts(),
            witness.metadata.sequence_start,
            witness.metadata.sequence_end,
            witness.metadata.timestamp,
            witness.num_events(),
            witness.all_compliant(),
            BatchPolicyKind::AmlThreshold,
            witness.policy_limit,
            witness.public_inputs_accumulator().unwrap(),
        );
        (proof.proof_bytes, public_inputs, new_root)
    }

    #[test]
    fn test_verify_chain_accepts_valid_linked_chain() {
        // Two batches where batch 2 starts from batch 1's new state root and
        // continues its sequence — the canonical L2 anchoring scenario.
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();

        let (p1, pi1, root1) =
            build_chained_batch(BatchStateRoot::genesis(), 0, tenant_id, store_id);
        let (p2, pi2, _root2) = build_chained_batch(root1, 1, tenant_id, store_id);

        let verifier = fast_verifier();
        let results = verifier
            .verify_chain(&[(p1, pi1), (p2, pi2)])
            .expect("valid linked chain should verify");
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.valid));
    }

    #[test]
    fn test_verify_chain_rejects_broken_state_root_linkage() {
        // Both batches are individually valid, but batch 2 starts from genesis
        // instead of batch 1's new state root, so the chain linkage is broken.
        // Sequence continuity and tenant/store match, so the failure must come
        // specifically from the state-root linkage check.
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();

        let (p1, pi1, _root1) =
            build_chained_batch(BatchStateRoot::genesis(), 0, tenant_id, store_id);
        let (p2, pi2, _root2) =
            build_chained_batch(BatchStateRoot::genesis(), 1, tenant_id, store_id);

        let verifier = fast_verifier();
        let err = verifier
            .verify_chain(&[(p1, pi1), (p2, pi2)])
            .expect_err("broken state-root linkage must be rejected");
        assert!(
            matches!(err, BatchError::InvalidStateChain { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn test_batch_proof_survives_json_round_trip_and_verifies() {
        // Mirrors the FFI/client transport path (ves_batch_prove_json -> wire ->
        // ves_batch_verify_json): a real proof serialized to JSON and back must
        // still verify against the public inputs recovered from that JSON. The
        // existing serialization tests only check field fidelity with placeholder
        // proof bytes, never that a genuine proof survives transport and verifies.
        use crate::serialization::SerializableBatchProof;

        let (proof, public_inputs) = sample_fast_batch_proof_full();

        let serializable = SerializableBatchProof::new(proof, public_inputs).unwrap();
        let json = serializable.to_json().unwrap();
        let restored = SerializableBatchProof::from_json(&json).unwrap();
        let restored_inputs = restored.to_batch_public_inputs().unwrap();

        let verifier = fast_verifier();
        let result = verifier
            .verify(&restored.proof.proof_bytes, &restored_inputs)
            .unwrap();
        assert!(
            result.valid,
            "round-tripped proof failed to verify: {:?}",
            result.error
        );
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
    fn test_chain_continuity_rejects_tenant_mismatch() {
        let prev_inputs = BatchPublicInputs {
            tenant_id: [felt_from_u64(1); 4],
            store_id: [felt_from_u64(7); 4],
            sequence_start: felt_from_u64(10),
            sequence_end: felt_from_u64(19),
            ..Default::default()
        };

        let next_inputs = BatchPublicInputs {
            tenant_id: [felt_from_u64(2); 4],
            store_id: [felt_from_u64(7); 4],
            sequence_start: felt_from_u64(20),
            sequence_end: felt_from_u64(29),
            ..Default::default()
        };

        let err = BatchVerifier::validate_sequence_continuity(&prev_inputs, &next_inputs, 1)
            .expect_err("tenant mismatch should fail");
        assert!(matches!(err, BatchError::InvalidPublicInputs(msg) if msg.contains("Tenant")));
    }

    #[test]
    fn test_chain_continuity_rejects_store_mismatch() {
        let prev_inputs = BatchPublicInputs {
            tenant_id: [felt_from_u64(1); 4],
            store_id: [felt_from_u64(7); 4],
            sequence_start: felt_from_u64(10),
            sequence_end: felt_from_u64(19),
            ..Default::default()
        };

        let next_inputs = BatchPublicInputs {
            tenant_id: [felt_from_u64(1); 4],
            store_id: [felt_from_u64(8); 4],
            sequence_start: felt_from_u64(20),
            sequence_end: felt_from_u64(29),
            ..Default::default()
        };

        let err = BatchVerifier::validate_sequence_continuity(&prev_inputs, &next_inputs, 1)
            .expect_err("store mismatch should fail");
        assert!(matches!(err, BatchError::InvalidPublicInputs(msg) if msg.contains("Store")));
    }

    #[test]
    fn test_chain_continuity_accepts_matching_tenant_store() {
        let prev_inputs = BatchPublicInputs {
            tenant_id: [felt_from_u64(1); 4],
            store_id: [felt_from_u64(7); 4],
            sequence_start: felt_from_u64(10),
            sequence_end: felt_from_u64(19),
            ..Default::default()
        };

        let next_inputs = BatchPublicInputs {
            tenant_id: [felt_from_u64(1); 4],
            store_id: [felt_from_u64(7); 4],
            sequence_start: felt_from_u64(20),
            sequence_end: felt_from_u64(29),
            ..Default::default()
        };

        assert!(BatchVerifier::validate_sequence_continuity(&prev_inputs, &next_inputs, 1).is_ok());
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

    #[test]
    fn test_verify_batch_proof_at_max_size_is_not_rejected_for_size() {
        let public_inputs = BatchPublicInputs::new(
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
        let big_proof = vec![0xAB; MAX_BATCH_PROOF_SIZE];

        // Should fail with deserialization, NOT ProofTooLarge
        let result = verify_batch_proof(&big_proof, &public_inputs);
        assert!(
            !matches!(result, Err(BatchError::ProofTooLarge { .. })),
            "proof at exactly MAX_BATCH_PROOF_SIZE should not be rejected for size"
        );
    }

    #[test]
    fn test_verify_batch_proof_over_max_size_is_rejected() {
        let public_inputs = BatchPublicInputs::new(
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
        let oversized_proof = vec![0xAB; MAX_BATCH_PROOF_SIZE + 1];

        let result = verify_batch_proof(&oversized_proof, &public_inputs);
        assert!(
            matches!(
                result,
                Err(BatchError::ProofTooLarge {
                    size,
                    max_size,
                }) if size == MAX_BATCH_PROOF_SIZE + 1 && max_size == MAX_BATCH_PROOF_SIZE
            ),
            "proof 1 byte over MAX_BATCH_PROOF_SIZE must be rejected: {result:?}"
        );
    }

    #[test]
    fn test_verify_batch_proof_rejects_oversized_batch_before_deserializing_proof() {
        let public_inputs = BatchPublicInputs::new(
            [felt_from_u64(1); 4],
            [felt_from_u64(2); 4],
            [felt_from_u64(3); 4],
            [felt_from_u64(4); 4],
            [felt_from_u64(5); 4],
            0,
            MAX_BATCH_SIZE as u64,
            123,
            MAX_BATCH_SIZE + 1,
            true,
            BatchPolicyKind::AmlThreshold,
            10_000,
            [felt_from_u64(9); 8],
        );

        let err = verify_batch_proof(b"not-a-proof", &public_inputs)
            .expect_err("oversized batches should fail before proof parsing");
        assert!(matches!(err, BatchError::InvalidPublicInputs(_)));
    }
}
