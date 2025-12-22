//! Batch witness types
//!
//! This module defines the witness structures for batch state transition proofs.
//! A batch witness contains multiple event witnesses plus batch-level metadata.

use uuid::Uuid;
use ves_stark_primitives::public_inputs::CompliancePublicInputs;
use ves_stark_primitives::{Felt, felt_from_u64, FELT_ZERO, FELT_ONE};

use crate::error::BatchError;
use crate::state::{BatchMetadata, BatchStateRoot, EventLeaf, EventMerkleTree};
use crate::air::trace_layout::MAX_BATCH_SIZE;

/// Witness for a single event within a batch
#[derive(Debug, Clone)]
pub struct BatchEventWitness {
    /// Event index within the batch (0-indexed)
    pub event_index: usize,

    /// The actual amount (private witness data)
    pub amount: u64,

    /// Public inputs for this event
    pub public_inputs: CompliancePublicInputs,

    /// Pre-computed compliance result
    pub is_compliant: bool,
}

impl BatchEventWitness {
    /// Create a new batch event witness
    pub fn new(
        event_index: usize,
        amount: u64,
        public_inputs: CompliancePublicInputs,
        threshold: u64,
    ) -> Self {
        let is_compliant = amount < threshold;
        Self {
            event_index,
            amount,
            public_inputs,
            is_compliant,
        }
    }

    /// Get amount as field element limbs (low to high, 8 x u32)
    pub fn amount_limbs(&self) -> [Felt; 8] {
        let mut limbs = [FELT_ZERO; 8];
        limbs[0] = felt_from_u64(self.amount & 0xFFFFFFFF);
        limbs[1] = felt_from_u64(self.amount >> 32);
        limbs
    }

    /// Convert to an event leaf for Merkle tree
    pub fn to_event_leaf(&self, policy_hash: &[Felt; 8]) -> EventLeaf {
        // Event ID from UUID
        let event_id = uuid_to_felts(&self.public_inputs.event_id);

        // Amount commitment (first 4 limbs)
        let amount_limbs = self.amount_limbs();
        let amount_commitment = [
            amount_limbs[0],
            amount_limbs[1],
            amount_limbs[2],
            amount_limbs[3],
        ];

        EventLeaf {
            event_id,
            amount_commitment,
            policy_hash: *policy_hash,
            compliance_flag: if self.is_compliant { FELT_ONE } else { FELT_ZERO },
        }
    }

    /// Get compliance flag as field element
    pub fn compliance_felt(&self) -> Felt {
        if self.is_compliant { FELT_ONE } else { FELT_ZERO }
    }
}

/// Witness for an entire batch of events
#[derive(Debug, Clone)]
pub struct BatchWitness {
    /// Events in this batch
    pub events: Vec<BatchEventWitness>,

    /// Batch metadata
    pub metadata: BatchMetadata,

    /// Previous state root (from prior batch)
    pub prev_state_root: BatchStateRoot,

    /// Policy hash (shared across all events)
    pub policy_hash: [Felt; 8],

    /// Policy threshold
    pub policy_limit: u64,
}

impl BatchWitness {
    /// Create a new batch witness
    pub fn new(
        events: Vec<BatchEventWitness>,
        metadata: BatchMetadata,
        prev_state_root: BatchStateRoot,
        policy_hash: [Felt; 8],
        policy_limit: u64,
    ) -> Self {
        Self {
            events,
            metadata,
            prev_state_root,
            policy_hash,
            policy_limit,
        }
    }

    /// Validate the batch witness
    pub fn validate(&self) -> Result<(), BatchError> {
        // Check batch size
        if self.events.is_empty() {
            return Err(BatchError::EmptyBatch);
        }

        if self.events.len() > MAX_BATCH_SIZE {
            return Err(BatchError::BatchTooLarge {
                size: self.events.len(),
                max: MAX_BATCH_SIZE,
            });
        }

        // Validate event indices are sequential
        for (i, event) in self.events.iter().enumerate() {
            if event.event_index != i {
                return Err(BatchError::InvalidWitness(format!(
                    "Event index mismatch: expected {}, got {}",
                    i, event.event_index
                )));
            }
        }

        Ok(())
    }

    /// Check if all events in the batch are compliant
    pub fn all_compliant(&self) -> bool {
        self.events.iter().all(|e| e.is_compliant)
    }

    /// Get the number of events
    pub fn num_events(&self) -> usize {
        self.events.len()
    }

    /// Build the event Merkle tree from the witnesses
    pub fn build_event_tree(&self) -> EventMerkleTree {
        let leaves: Vec<EventLeaf> = self.events
            .iter()
            .map(|e| e.to_event_leaf(&self.policy_hash))
            .collect();

        // Note: from_leaves returns Result, unwrap since we know leaves are valid
        EventMerkleTree::from_leaves(leaves).expect("Failed to build event tree")
    }

    /// Compute the new state root for this batch
    pub fn compute_new_state_root(&self) -> BatchStateRoot {
        let event_tree = self.build_event_tree();
        BatchStateRoot::compute(&event_tree, &self.metadata)
    }

    /// Get batch ID as field elements
    pub fn batch_id_felts(&self) -> [Felt; 4] {
        uuid_to_felts(&self.metadata.batch_id)
    }

    /// Get tenant ID as field elements
    pub fn tenant_id_felts(&self) -> [Felt; 4] {
        uuid_to_felts(&self.metadata.tenant_id)
    }

    /// Get store ID as field elements
    pub fn store_id_felts(&self) -> [Felt; 4] {
        uuid_to_felts(&self.metadata.store_id)
    }
}

/// Builder for creating batch witnesses
pub struct BatchWitnessBuilder {
    events: Vec<BatchEventWitness>,
    metadata: Option<BatchMetadata>,
    prev_state_root: Option<BatchStateRoot>,
    policy_hash: Option<[Felt; 8]>,
    policy_limit: Option<u64>,
}

impl BatchWitnessBuilder {
    /// Create a new batch witness builder
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            metadata: None,
            prev_state_root: None,
            policy_hash: None,
            policy_limit: None,
        }
    }

    /// Set the batch metadata
    pub fn metadata(mut self, metadata: BatchMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Set the previous state root
    pub fn prev_state_root(mut self, root: BatchStateRoot) -> Self {
        self.prev_state_root = Some(root);
        self
    }

    /// Set the policy hash
    pub fn policy_hash(mut self, hash: [Felt; 8]) -> Self {
        self.policy_hash = Some(hash);
        self
    }

    /// Set the policy limit
    pub fn policy_limit(mut self, limit: u64) -> Self {
        self.policy_limit = Some(limit);
        self
    }

    /// Add an event to the batch
    pub fn add_event(
        mut self,
        amount: u64,
        public_inputs: CompliancePublicInputs,
    ) -> Self {
        let threshold = self.policy_limit.unwrap_or(u64::MAX);
        let event = BatchEventWitness::new(
            self.events.len(),
            amount,
            public_inputs,
            threshold,
        );
        self.events.push(event);
        self
    }

    /// Add multiple events to the batch
    pub fn add_events(
        mut self,
        events: Vec<(u64, CompliancePublicInputs)>,
    ) -> Self {
        let threshold = self.policy_limit.unwrap_or(u64::MAX);
        for (amount, public_inputs) in events {
            let event = BatchEventWitness::new(
                self.events.len(),
                amount,
                public_inputs,
                threshold,
            );
            self.events.push(event);
        }
        self
    }

    /// Build the batch witness
    pub fn build(self) -> Result<BatchWitness, BatchError> {
        let metadata = self.metadata
            .ok_or_else(|| BatchError::InvalidWitness("Metadata is required".to_string()))?;

        let prev_state_root = self.prev_state_root
            .unwrap_or_else(BatchStateRoot::genesis);

        let policy_hash = self.policy_hash
            .ok_or_else(|| BatchError::InvalidWitness("Policy hash is required".to_string()))?;

        let policy_limit = self.policy_limit
            .ok_or_else(|| BatchError::InvalidWitness("Policy limit is required".to_string()))?;

        let witness = BatchWitness::new(
            self.events,
            metadata,
            prev_state_root,
            policy_hash,
            policy_limit,
        );

        witness.validate()?;
        Ok(witness)
    }
}

impl Default for BatchWitnessBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a UUID to 4 field elements
fn uuid_to_felts(uuid: &Uuid) -> [Felt; 4] {
    let bytes = uuid.as_bytes();
    [
        felt_from_u64(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64),
        felt_from_u64(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as u64),
        felt_from_u64(u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as u64),
        felt_from_u64(u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as u64),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ves_stark_primitives::public_inputs::{PolicyParams, compute_policy_hash};

    fn sample_public_inputs(threshold: u64, event_index: usize) -> CompliancePublicInputs {
        let policy_id = "aml.threshold";
        let params = PolicyParams::threshold(threshold);
        let hash = compute_policy_hash(policy_id, &params);

        CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            sequence_number: event_index as u64,
            payload_kind: 1,
            payload_plain_hash: "0".repeat(64),
            payload_cipher_hash: "0".repeat(64),
            event_signing_hash: "0".repeat(64),
            policy_id: policy_id.to_string(),
            policy_params: params,
            policy_hash: hash.to_hex(),
        }
    }

    fn sample_policy_hash(threshold: u64) -> [Felt; 8] {
        let policy_id = "aml.threshold";
        let params = PolicyParams::threshold(threshold);
        let hash = compute_policy_hash(policy_id, &params);
        ves_stark_primitives::hash_to_felts(&hash)
    }

    #[test]
    fn test_batch_event_witness() {
        let threshold = 10000u64;
        let inputs = sample_public_inputs(threshold, 0);
        let witness = BatchEventWitness::new(0, 5000, inputs, threshold);

        assert!(witness.is_compliant);
        assert_eq!(witness.event_index, 0);
        assert_eq!(witness.amount, 5000);
    }

    #[test]
    fn test_batch_event_witness_non_compliant() {
        let threshold = 10000u64;
        let inputs = sample_public_inputs(threshold, 0);
        let witness = BatchEventWitness::new(0, 15000, inputs, threshold);

        assert!(!witness.is_compliant);
    }

    #[test]
    fn test_batch_witness_builder() {
        let threshold = 10000u64;
        let policy_hash = sample_policy_hash(threshold);
        let metadata = BatchMetadata::with_ids(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            0,
            9,
        );

        let mut builder = BatchWitnessBuilder::new()
            .metadata(metadata)
            .policy_hash(policy_hash)
            .policy_limit(threshold);

        // Add 10 events
        for i in 0..10 {
            let inputs = sample_public_inputs(threshold, i);
            builder = builder.add_event(5000 + i as u64 * 100, inputs);
        }

        let witness = builder.build().unwrap();

        assert_eq!(witness.num_events(), 10);
        assert!(witness.all_compliant());
    }

    #[test]
    fn test_batch_witness_validation_empty() {
        let threshold = 10000u64;
        let policy_hash = sample_policy_hash(threshold);
        let metadata = BatchMetadata::with_ids(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            0,
            0,
        );

        let result = BatchWitnessBuilder::new()
            .metadata(metadata)
            .policy_hash(policy_hash)
            .policy_limit(threshold)
            .build();

        assert!(matches!(result, Err(BatchError::EmptyBatch)));
    }

    #[test]
    fn test_batch_witness_compute_state_root() {
        let threshold = 10000u64;
        let policy_hash = sample_policy_hash(threshold);
        let metadata = BatchMetadata::with_ids(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            0,
            3,
        );

        let mut builder = BatchWitnessBuilder::new()
            .metadata(metadata)
            .policy_hash(policy_hash)
            .policy_limit(threshold);

        for i in 0..4 {
            let inputs = sample_public_inputs(threshold, i);
            builder = builder.add_event(5000, inputs);
        }

        let witness = builder.build().unwrap();
        let new_root = witness.compute_new_state_root();

        // Root should be non-zero
        assert!(new_root.root.iter().any(|f| *f != FELT_ZERO));
    }
}
