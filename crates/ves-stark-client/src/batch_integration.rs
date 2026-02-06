//! Batch proof integration with ves-stark-batch
//!
//! This module provides helpers for submitting batch proofs from ves-stark-batch
//! to Set Chain.

use uuid::Uuid;

use crate::error::{ClientError, Result};
use crate::set_chain::{BatchProofResponse, BatchProofSubmission, SetChainClient};

/// Extension trait for SetChainClient to handle BatchProof from ves-stark-batch
impl SetChainClient {
    /// Submit a batch proof from ves-stark-batch to Set Chain
    ///
    /// This is a convenience method that converts a BatchProof and its metadata
    /// into a BatchProofSubmission and submits it via the sequencer.
    ///
    /// # Arguments
    ///
    /// * `proof` - The batch proof from ves-stark-batch
    /// * `tenant_id` - Tenant UUID
    /// * `store_id` - Store UUID
    /// * `events_root` - Merkle root of events (32 bytes)
    /// * `sequence_start` - First sequence number
    /// * `sequence_end` - Last sequence number
    /// * `policy_hash` - Policy hash (32 bytes)
    /// * `policy_limit` - Policy limit/threshold
    pub async fn submit_batch_proof_from_batch(
        &self,
        proof: &ves_stark_batch::prover::BatchProof,
        tenant_id: Uuid,
        store_id: Uuid,
        events_root: [u8; 32],
        sequence_start: u64,
        sequence_end: u64,
        policy_hash: [u8; 32],
        policy_limit: u64,
    ) -> Result<BatchProofResponse> {
        // Parse batch_id from hex string
        let batch_id = Uuid::parse_str(&proof.metadata.batch_id).unwrap_or_else(|_| {
            // If batch_id is a hex string but not a UUID, create one from the hash
            let bytes = hex::decode(&proof.metadata.batch_id).unwrap_or_else(|_| vec![0u8; 16]);
            let mut uuid_bytes = [0u8; 16];
            uuid_bytes.copy_from_slice(&bytes[..16.min(bytes.len())]);
            Uuid::from_bytes(uuid_bytes)
        });

        // Convert state roots from [u64; 4] to [u8; 32]
        let prev_state_root = u64_array_to_bytes(&proof.prev_state_root);
        let new_state_root = u64_array_to_bytes(&proof.new_state_root);

        let submission = SetChainClient::create_submission(
            batch_id,
            tenant_id,
            store_id,
            events_root,
            prev_state_root,
            new_state_root,
            sequence_start,
            sequence_end,
            proof.metadata.num_events as u32,
            &proof.proof_bytes,
            policy_hash,
            policy_limit,
            proof.metadata.all_compliant,
        );

        self.submit_batch_proof(submission).await
    }

    /// Submit a batch proof with combined batch commitment
    ///
    /// This is more gas-efficient as it commits the batch and proof in one transaction.
    pub async fn submit_batch_proof_from_batch_combined(
        &self,
        proof: &ves_stark_batch::prover::BatchProof,
        tenant_id: Uuid,
        store_id: Uuid,
        events_root: [u8; 32],
        sequence_start: u64,
        sequence_end: u64,
        policy_hash: [u8; 32],
        policy_limit: u64,
    ) -> Result<BatchProofResponse> {
        // Parse batch_id from hex string
        let batch_id = Uuid::parse_str(&proof.metadata.batch_id).unwrap_or_else(|_| {
            let bytes = hex::decode(&proof.metadata.batch_id).unwrap_or_else(|_| vec![0u8; 16]);
            let mut uuid_bytes = [0u8; 16];
            uuid_bytes.copy_from_slice(&bytes[..16.min(bytes.len())]);
            Uuid::from_bytes(uuid_bytes)
        });

        let prev_state_root = u64_array_to_bytes(&proof.prev_state_root);
        let new_state_root = u64_array_to_bytes(&proof.new_state_root);

        let submission = SetChainClient::create_submission(
            batch_id,
            tenant_id,
            store_id,
            events_root,
            prev_state_root,
            new_state_root,
            sequence_start,
            sequence_end,
            proof.metadata.num_events as u32,
            &proof.proof_bytes,
            policy_hash,
            policy_limit,
            proof.metadata.all_compliant,
        );

        self.submit_batch_with_proof(submission, proof.metadata.proving_time_ms)
            .await
    }

    /// Verify a batch proof hash against the on-chain record
    pub async fn verify_batch_proof_from_batch(
        &self,
        proof: &ves_stark_batch::prover::BatchProof,
    ) -> Result<bool> {
        // Parse batch_id
        let batch_id = Uuid::parse_str(&proof.metadata.batch_id).unwrap_or_else(|_| {
            let bytes = hex::decode(&proof.metadata.batch_id).unwrap_or_else(|_| vec![0u8; 16]);
            let mut uuid_bytes = [0u8; 16];
            uuid_bytes.copy_from_slice(&bytes[..16.min(bytes.len())]);
            Uuid::from_bytes(uuid_bytes)
        });

        let verification = self.verify_proof_hash(batch_id, &proof.proof_hash).await?;
        Ok(verification.proof_hash_valid)
    }
}

/// Convert a 4-element u64 array to a 32-byte array
fn u64_array_to_bytes(arr: &[u64; 4]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, &val) in arr.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&val.to_le_bytes());
    }
    bytes
}

/// Builder for batch proof submissions
pub struct BatchSubmissionBuilder {
    batch_id: Option<Uuid>,
    tenant_id: Option<Uuid>,
    store_id: Option<Uuid>,
    events_root: Option<[u8; 32]>,
    prev_state_root: Option<[u8; 32]>,
    new_state_root: Option<[u8; 32]>,
    sequence_start: Option<u64>,
    sequence_end: Option<u64>,
    event_count: Option<u32>,
    proof_bytes: Option<Vec<u8>>,
    policy_hash: Option<[u8; 32]>,
    policy_limit: Option<u64>,
    all_compliant: bool,
}

impl BatchSubmissionBuilder {
    pub fn new() -> Self {
        Self {
            batch_id: None,
            tenant_id: None,
            store_id: None,
            events_root: None,
            prev_state_root: None,
            new_state_root: None,
            sequence_start: None,
            sequence_end: None,
            event_count: None,
            proof_bytes: None,
            policy_hash: None,
            policy_limit: None,
            all_compliant: true,
        }
    }

    pub fn from_batch_proof(proof: &ves_stark_batch::prover::BatchProof) -> Self {
        let batch_id = Uuid::parse_str(&proof.metadata.batch_id).unwrap_or_else(|_| {
            let bytes = hex::decode(&proof.metadata.batch_id).unwrap_or_else(|_| vec![0u8; 16]);
            let mut uuid_bytes = [0u8; 16];
            uuid_bytes.copy_from_slice(&bytes[..16.min(bytes.len())]);
            Uuid::from_bytes(uuid_bytes)
        });

        Self {
            batch_id: Some(batch_id),
            tenant_id: None,
            store_id: None,
            events_root: None,
            prev_state_root: Some(u64_array_to_bytes(&proof.prev_state_root)),
            new_state_root: Some(u64_array_to_bytes(&proof.new_state_root)),
            sequence_start: None,
            sequence_end: None,
            event_count: Some(proof.metadata.num_events as u32),
            proof_bytes: Some(proof.proof_bytes.clone()),
            policy_hash: None,
            policy_limit: None,
            all_compliant: proof.metadata.all_compliant,
        }
    }

    pub fn batch_id(mut self, id: Uuid) -> Self {
        self.batch_id = Some(id);
        self
    }

    pub fn tenant_id(mut self, id: Uuid) -> Self {
        self.tenant_id = Some(id);
        self
    }

    pub fn store_id(mut self, id: Uuid) -> Self {
        self.store_id = Some(id);
        self
    }

    pub fn events_root(mut self, root: [u8; 32]) -> Self {
        self.events_root = Some(root);
        self
    }

    pub fn prev_state_root(mut self, root: [u8; 32]) -> Self {
        self.prev_state_root = Some(root);
        self
    }

    pub fn new_state_root(mut self, root: [u8; 32]) -> Self {
        self.new_state_root = Some(root);
        self
    }

    pub fn sequence_range(mut self, start: u64, end: u64) -> Self {
        self.sequence_start = Some(start);
        self.sequence_end = Some(end);
        self
    }

    pub fn event_count(mut self, count: u32) -> Self {
        self.event_count = Some(count);
        self
    }

    pub fn proof_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.proof_bytes = Some(bytes);
        self
    }

    pub fn policy_hash(mut self, hash: [u8; 32]) -> Self {
        self.policy_hash = Some(hash);
        self
    }

    pub fn policy_limit(mut self, limit: u64) -> Self {
        self.policy_limit = Some(limit);
        self
    }

    pub fn all_compliant(mut self, compliant: bool) -> Self {
        self.all_compliant = compliant;
        self
    }

    pub fn build(self) -> Result<BatchProofSubmission> {
        let batch_id = self.batch_id.ok_or_else(|| ClientError::ApiError {
            status: 400,
            message: "batch_id is required".to_string(),
        })?;
        let tenant_id = self.tenant_id.ok_or_else(|| ClientError::ApiError {
            status: 400,
            message: "tenant_id is required".to_string(),
        })?;
        let store_id = self.store_id.ok_or_else(|| ClientError::ApiError {
            status: 400,
            message: "store_id is required".to_string(),
        })?;
        let events_root = self.events_root.ok_or_else(|| ClientError::ApiError {
            status: 400,
            message: "events_root is required".to_string(),
        })?;
        let prev_state_root = self.prev_state_root.ok_or_else(|| ClientError::ApiError {
            status: 400,
            message: "prev_state_root is required".to_string(),
        })?;
        let new_state_root = self.new_state_root.ok_or_else(|| ClientError::ApiError {
            status: 400,
            message: "new_state_root is required".to_string(),
        })?;
        let sequence_start = self.sequence_start.ok_or_else(|| ClientError::ApiError {
            status: 400,
            message: "sequence_start is required".to_string(),
        })?;
        let sequence_end = self.sequence_end.ok_or_else(|| ClientError::ApiError {
            status: 400,
            message: "sequence_end is required".to_string(),
        })?;
        let event_count = self.event_count.ok_or_else(|| ClientError::ApiError {
            status: 400,
            message: "event_count is required".to_string(),
        })?;
        let proof_bytes = self.proof_bytes.ok_or_else(|| ClientError::ApiError {
            status: 400,
            message: "proof_bytes is required".to_string(),
        })?;
        let policy_hash = self.policy_hash.ok_or_else(|| ClientError::ApiError {
            status: 400,
            message: "policy_hash is required".to_string(),
        })?;
        let policy_limit = self.policy_limit.ok_or_else(|| ClientError::ApiError {
            status: 400,
            message: "policy_limit is required".to_string(),
        })?;

        Ok(SetChainClient::create_submission(
            batch_id,
            tenant_id,
            store_id,
            events_root,
            prev_state_root,
            new_state_root,
            sequence_start,
            sequence_end,
            event_count,
            &proof_bytes,
            policy_hash,
            policy_limit,
            self.all_compliant,
        ))
    }
}

impl Default for BatchSubmissionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ves_stark_batch::prover::{BatchProof, BatchProofMetadata};

    fn sample_batch_proof() -> BatchProof {
        BatchProof {
            proof_bytes: vec![1, 2, 3, 4, 5],
            proof_hash: "0x1234567890abcdef".to_string(),
            prev_state_root: [1, 2, 3, 4],
            new_state_root: [5, 6, 7, 8],
            metadata: BatchProofMetadata {
                batch_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                num_events: 10,
                all_compliant: true,
                proving_time_ms: 100,
                trace_length: 256,
                proof_size: 5,
                prover_version: "0.1.0".to_string(),
            },
        }
    }

    #[test]
    fn test_u64_array_to_bytes() {
        let arr = [1u64, 2u64, 3u64, 4u64];
        let bytes = u64_array_to_bytes(&arr);
        assert_eq!(bytes.len(), 32);

        // Verify first u64 is correctly converted
        let recovered = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        assert_eq!(recovered, 1u64);
    }

    #[test]
    fn test_batch_submission_builder() {
        let proof = sample_batch_proof();
        let builder = BatchSubmissionBuilder::from_batch_proof(&proof)
            .tenant_id(Uuid::new_v4())
            .store_id(Uuid::new_v4())
            .events_root([0u8; 32])
            .sequence_range(1, 10)
            .policy_hash([0u8; 32])
            .policy_limit(10000);

        let submission = builder.build().unwrap();
        assert_eq!(submission.event_count, 10);
        assert!(submission.all_compliant);
    }

    #[test]
    fn test_batch_submission_builder_missing_field() {
        let proof = sample_batch_proof();
        let builder = BatchSubmissionBuilder::from_batch_proof(&proof);

        // Missing tenant_id should error
        let result = builder.build();
        assert!(result.is_err());
    }
}
