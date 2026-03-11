//! Batch witness types
//!
//! This module defines the witness structures for batch state transition proofs.
//! A batch witness contains multiple event witnesses plus batch-level metadata.

use std::collections::HashSet;
use uuid::Uuid;
use ves_stark_air::policy::Policy;
use ves_stark_primitives::public_inputs::CompliancePublicInputs;
use ves_stark_primitives::rescue::rescue_hash;
use ves_stark_primitives::{
    felt_from_u64, felts_to_hash, hash_to_felts, Felt, FELT_ONE, FELT_ZERO,
};

use crate::air::trace_layout::MAX_BATCH_SIZE;
use crate::error::{BatchError, BatchResult};
use crate::state::{BatchMetadata, BatchStateRoot, EventLeaf, EventMerkleTree};

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
    ) -> Result<Self, BatchError> {
        let policy =
            Policy::from_public_inputs(&public_inputs.policy_id, &public_inputs.policy_params)
                .map_err(|e| {
                    BatchError::InvalidWitness(format!(
                        "Event {event_index} failed to parse policy: {e}"
                    ))
                })?;

        if policy.limit() != threshold {
            return Err(BatchError::InvalidWitness(format!(
                "Event {event_index} policy limit mismatch: event policy limit {}, expected {}",
                policy.limit(),
                threshold
            )));
        }

        let is_compliant = policy.validate_amount(amount);
        Ok(Self {
            event_index,
            amount,
            public_inputs,
            is_compliant,
        })
    }

    /// Parse the compliance policy from public inputs.
    pub fn parsed_policy(&self) -> Result<Policy, BatchError> {
        Policy::from_public_inputs(
            &self.public_inputs.policy_id,
            &self.public_inputs.policy_params,
        )
        .map_err(|e| {
            BatchError::InvalidWitness(format!(
                "Event {} policy parse failed: {e}",
                self.event_index
            ))
        })
    }

    /// Get amount as field element limbs (low to high, 8 x u32)
    pub fn amount_limbs(&self) -> [Felt; 8] {
        let mut limbs = [FELT_ZERO; 8];
        limbs[0] = felt_from_u64(self.amount & 0xFFFFFFFF);
        limbs[1] = felt_from_u64(self.amount >> 32);
        limbs
    }

    /// Compute the Rescue commitment to the private amount.
    pub fn amount_commitment(&self) -> [Felt; 4] {
        rescue_hash(&self.amount_limbs())
    }

    /// Compute the canonical hash of the event's public inputs.
    pub fn canonical_public_inputs_hash(&self) -> Result<[Felt; 8], BatchError> {
        self.public_inputs
            .compute_hash()
            .map(|hash| hash_to_felts(&hash))
            .map_err(|e| {
                BatchError::InvalidWitness(format!(
                    "Event {} canonical public-input hash computation failed: {e}",
                    self.event_index
                ))
            })
    }

    /// Convert to an event leaf for Merkle tree
    pub fn to_event_leaf(&self, policy_hash: &[Felt; 8]) -> Result<EventLeaf, BatchError> {
        // Event ID from UUID
        let event_id = uuid_to_felts(&self.public_inputs.event_id);

        Ok(EventLeaf {
            event_id,
            amount_commitment: self.amount_commitment(),
            policy_hash: *policy_hash,
            public_inputs_hash: self.canonical_public_inputs_hash()?,
            compliance_flag: if self.is_compliant {
                FELT_ONE
            } else {
                FELT_ZERO
            },
        })
    }

    /// Get compliance flag as field element
    pub fn compliance_felt(&self) -> Felt {
        if self.is_compliant {
            FELT_ONE
        } else {
            FELT_ZERO
        }
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

        // Validate metadata sequence range.
        if self.metadata.sequence_start > self.metadata.sequence_end {
            return Err(BatchError::InvalidWitness(format!(
                "Invalid metadata sequence range: start {} is greater than end {}",
                self.metadata.sequence_start, self.metadata.sequence_end
            )));
        }

        let declared_sequence_count = self
            .metadata
            .sequence_end
            .checked_sub(self.metadata.sequence_start)
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| {
                BatchError::InvalidWitness("Metadata sequence range overflows u64".to_string())
            })?;
        if declared_sequence_count != self.events.len() as u64 {
            return Err(BatchError::InvalidWitness(format!(
                "Sequence range length mismatch: expected {}, got {}",
                declared_sequence_count,
                self.events.len()
            )));
        }

        let batch_policy_hash_hex = felts_to_hash(&self.policy_hash).to_hex();
        let mut batch_policy: Option<Policy> = None;
        let mut seen_event_ids: HashSet<Uuid> = HashSet::with_capacity(self.events.len());

        // Validate per-event policy and sequence consistency
        for (i, event) in self.events.iter().enumerate() {
            if !seen_event_ids.insert(event.public_inputs.event_id) {
                return Err(BatchError::InvalidWitness(format!(
                    "Duplicate event_id {} at index {}",
                    event.public_inputs.event_id, event.event_index
                )));
            }

            // Validate witness-specific event index.
            if event.event_index != i {
                return Err(BatchError::InvalidWitness(format!(
                    "Event index mismatch: expected {}, got {}",
                    i, event.event_index
                )));
            }

            // Validate event metadata sequence continuity and bounds.
            let expected_sequence = self.metadata.sequence_start + i as u64;
            if event.public_inputs.sequence_number != expected_sequence {
                return Err(BatchError::InvalidWitness(format!(
                    "Event {} sequence mismatch: expected {}, got {}",
                    event.event_index, expected_sequence, event.public_inputs.sequence_number
                )));
            }

            // Validate tenant/store identity matches batch metadata.
            if event.public_inputs.tenant_id != self.metadata.tenant_id {
                return Err(BatchError::InvalidWitness(format!(
                    "Event {} tenant id does not match batch tenant id",
                    event.event_index
                )));
            }
            if event.public_inputs.store_id != self.metadata.store_id {
                return Err(BatchError::InvalidWitness(format!(
                    "Event {} store id does not match batch store id",
                    event.event_index
                )));
            }

            // Validate policy and policy hash.
            let event_policy = event.parsed_policy()?;
            if event.public_inputs.policy_hash != batch_policy_hash_hex {
                return Err(BatchError::InvalidWitness(format!(
                    "Event {} policy hash mismatch with batch policy hash",
                    event.event_index
                )));
            }

            let policy_hash_valid = event.public_inputs.validate_policy_hash().map_err(|e| {
                BatchError::InvalidWitness(format!(
                    "Event {} policy hash validation failed: {e}",
                    event.event_index
                ))
            })?;
            if !policy_hash_valid {
                return Err(BatchError::InvalidWitness(format!(
                    "Event {} policy hash does not match computed policy hash",
                    event.event_index
                )));
            }

            if let Some(policy) = &batch_policy {
                if policy != &event_policy {
                    return Err(BatchError::InvalidWitness(format!(
                        "Event {} policy mismatch: expected {:?}, got {:?}",
                        event.event_index, policy, event_policy
                    )));
                }
            } else {
                if event_policy.limit() != self.policy_limit {
                    return Err(BatchError::InvalidWitness(format!(
                        "Batch policy limit mismatch: batch limit {}, event {} limit {}",
                        self.policy_limit,
                        event.event_index,
                        event_policy.limit()
                    )));
                }
                batch_policy = Some(event_policy);
            }

            // Validate witness-computed compliance status.
            let expected_compliant = batch_policy
                .as_ref()
                .ok_or_else(|| {
                    BatchError::InvalidWitness(format!(
                        "Event {} batch policy was not initialized before validation",
                        event.event_index
                    ))
                })?
                .validate_amount(event.amount);
            if event.is_compliant != expected_compliant {
                return Err(BatchError::InvalidWitness(format!(
                    "Event {} compliance flag mismatch: expected {}, got {}",
                    event.event_index, expected_compliant, event.is_compliant
                )));
            }

            // Witness-commitment binding.
            let expected_commitment = event
                .public_inputs
                .witness_commitment_u64()
                .map_err(|e| {
                    BatchError::InvalidWitness(format!(
                        "Event {} witness commitment parse failed: {e}",
                        event.event_index
                    ))
                })?
                .ok_or_else(|| {
                    BatchError::InvalidWitness(format!(
                        "Event {} missing witness commitment",
                        event.event_index
                    ))
                })?;

            let actual_commitment = compute_amount_commitment_u64(&event.amount_limbs());
            if expected_commitment != actual_commitment {
                return Err(BatchError::InvalidWitness(format!(
                    "Event {} witness commitment mismatch: expected {:?}, got {:?}",
                    event.event_index, expected_commitment, actual_commitment
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

    /// Build the event Merkle tree from the witnesses.
    pub fn build_event_tree(&self) -> BatchResult<EventMerkleTree> {
        let leaves: Vec<EventLeaf> = self
            .events
            .iter()
            .map(|e| e.to_event_leaf(&self.policy_hash))
            .collect::<Result<Vec<_>, _>>()?;

        EventMerkleTree::from_leaves(leaves)
    }

    /// Compute the new state root for this batch
    pub fn compute_new_state_root(&self) -> BatchResult<BatchStateRoot> {
        let event_tree = self.build_event_tree()?;
        Ok(BatchStateRoot::compute(&event_tree, &self.metadata))
    }

    /// Compute the ordered accumulator over canonical per-event public-input hashes.
    pub fn public_inputs_accumulator(&self) -> BatchResult<[Felt; 8]> {
        let gamma = Felt::new(crate::air::trace_layout::MERKLE_LINK_GAMMA);
        let mut acc = [FELT_ZERO; 8];

        for event in &self.events {
            let public_inputs_hash = event.canonical_public_inputs_hash()?;
            for i in 0..8 {
                acc[i] = acc[i] * gamma + public_inputs_hash[i];
            }
        }

        Ok(acc)
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

impl BatchWitness {
    /// Parse the batch policy from the first event.
    pub(crate) fn policy(&self) -> Result<Policy, BatchError> {
        if self.events.is_empty() {
            return Err(BatchError::EmptyBatch);
        }
        self.events[0].parsed_policy()
    }
}

/// Builder for creating batch witnesses
#[derive(Debug)]
pub struct BatchWitnessBuilder {
    events: Vec<BatchEventWitness>,
    metadata: Option<BatchMetadata>,
    prev_state_root: Option<BatchStateRoot>,
    policy_hash: Option<[Felt; 8]>,
    policy_limit: Option<u64>,
}

impl BatchWitnessBuilder {
    fn ensure_additional_events_fit(&self, additional: usize) -> Result<(), BatchError> {
        let projected_len = self.events.len().checked_add(additional).ok_or_else(|| {
            BatchError::InvalidWitness("Batch size overflow while adding events".to_string())
        })?;

        if projected_len > MAX_BATCH_SIZE {
            return Err(BatchError::BatchTooLarge {
                size: projected_len,
                max: MAX_BATCH_SIZE,
            });
        }

        Ok(())
    }

    fn resolve_policy_context(
        &mut self,
        event_index: usize,
        public_inputs: &CompliancePublicInputs,
    ) -> Result<u64, BatchError> {
        let policy =
            Policy::from_public_inputs(&public_inputs.policy_id, &public_inputs.policy_params)
                .map_err(|e| {
                    BatchError::InvalidWitness(format!(
                        "Event {event_index} failed to parse policy: {e}"
                    ))
                })?;
        let policy_limit = policy.limit();

        if let Some(expected_limit) = self.policy_limit {
            if expected_limit != policy_limit {
                return Err(BatchError::InvalidWitness(format!(
                    "Event {event_index} policy limit mismatch: builder limit {expected_limit}, event limit {policy_limit}"
                )));
            }
        } else {
            self.policy_limit = Some(policy_limit);
        }

        let policy_hash_valid = public_inputs.validate_policy_hash().map_err(|e| {
            BatchError::InvalidWitness(format!(
                "Event {event_index} policy hash validation failed: {e}"
            ))
        })?;
        if !policy_hash_valid {
            return Err(BatchError::InvalidWitness(format!(
                "Event {event_index} policy hash does not match computed policy hash"
            )));
        }

        let computed_policy_hash = CompliancePublicInputs::compute_policy_hash(
            &public_inputs.policy_id,
            &public_inputs.policy_params,
        )
        .map_err(|e| {
            BatchError::InvalidWitness(format!(
                "Event {event_index} policy hash computation failed: {e}"
            ))
        })?;
        let policy_hash = hash_to_felts(&computed_policy_hash);

        if let Some(expected_hash) = self.policy_hash {
            if expected_hash != policy_hash {
                return Err(BatchError::InvalidWitness(format!(
                    "Event {event_index} policy hash mismatch with builder policy hash"
                )));
            }
        } else {
            self.policy_hash = Some(policy_hash);
        }

        Ok(policy_limit)
    }

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

    /// Add an event to the batch.
    ///
    /// If `policy_limit` / `policy_hash` were not configured explicitly, they are inferred
    /// from the event's canonical public inputs on the first add.
    pub fn add_event(
        mut self,
        amount: u64,
        public_inputs: CompliancePublicInputs,
    ) -> Result<Self, BatchError> {
        self.ensure_additional_events_fit(1)?;
        let threshold = self.resolve_policy_context(self.events.len(), &public_inputs)?;
        let event = BatchEventWitness::new(self.events.len(), amount, public_inputs, threshold)?;
        self.events.push(event);
        Ok(self)
    }

    /// Add multiple events to the batch.
    ///
    /// If `policy_limit` / `policy_hash` were not configured explicitly, they are inferred
    /// from the first event and then enforced across the remainder.
    pub fn add_events(
        mut self,
        events: Vec<(u64, CompliancePublicInputs)>,
    ) -> Result<Self, BatchError> {
        self.ensure_additional_events_fit(events.len())?;
        for (amount, public_inputs) in events {
            let threshold = self.resolve_policy_context(self.events.len(), &public_inputs)?;
            let event =
                BatchEventWitness::new(self.events.len(), amount, public_inputs, threshold)?;
            self.events.push(event);
        }
        Ok(self)
    }

    /// Build the batch witness
    pub fn build(self) -> Result<BatchWitness, BatchError> {
        if self.events.is_empty() {
            return Err(BatchError::EmptyBatch);
        }

        let metadata = self
            .metadata
            .ok_or_else(|| BatchError::InvalidWitness("Metadata is required".to_string()))?;

        let prev_state_root = self.prev_state_root.unwrap_or_else(BatchStateRoot::genesis);

        let policy_hash = self.policy_hash.ok_or_else(|| {
            BatchError::InvalidWitness("Policy hash could not be determined".to_string())
        })?;

        let policy_limit = self.policy_limit.ok_or_else(|| {
            BatchError::InvalidWitness("Policy limit could not be determined".to_string())
        })?;

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

fn compute_amount_commitment_u64(amount_limbs: &[Felt; 8]) -> [u64; 4] {
    let hash_output = rescue_hash(amount_limbs);
    [
        hash_output[0].as_int(),
        hash_output[1].as_int(),
        hash_output[2].as_int(),
        hash_output[3].as_int(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ves_stark_primitives::public_inputs::{
        compute_policy_hash, witness_commitment_u64_to_hex, PolicyParams,
    };

    fn sample_public_inputs_with_policy(
        policy_id: &str,
        params: PolicyParams,
        amount: u64,
        event_index: usize,
        tenant_id: Uuid,
        store_id: Uuid,
    ) -> CompliancePublicInputs {
        let hash = compute_policy_hash(policy_id, &params).unwrap();
        let mut amount_limbs = [FELT_ZERO; 8];
        amount_limbs[0] = felt_from_u64(amount & 0xFFFFFFFF);
        amount_limbs[1] = felt_from_u64(amount >> 32);
        let commitment = compute_amount_commitment_u64(&amount_limbs);

        CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id,
            store_id,
            sequence_number: event_index as u64,
            payload_kind: 1,
            payload_plain_hash: "0".repeat(64),
            payload_cipher_hash: "0".repeat(64),
            event_signing_hash: "0".repeat(64),
            policy_id: policy_id.to_string(),
            policy_params: params,
            policy_hash: hash.to_hex(),
            witness_commitment: Some(witness_commitment_u64_to_hex(&commitment)),
        }
    }

    fn sample_public_inputs(
        threshold: u64,
        amount: u64,
        event_index: usize,
        tenant_id: Uuid,
        store_id: Uuid,
    ) -> CompliancePublicInputs {
        sample_public_inputs_with_policy(
            "aml.threshold",
            PolicyParams::threshold(threshold),
            amount,
            event_index,
            tenant_id,
            store_id,
        )
    }

    fn sample_policy_hash(threshold: u64) -> [Felt; 8] {
        let policy_id = "aml.threshold";
        let params = PolicyParams::threshold(threshold);
        let hash = compute_policy_hash(policy_id, &params).unwrap();
        ves_stark_primitives::hash_to_felts(&hash)
    }

    #[test]
    fn test_batch_event_witness() {
        let threshold = 10000u64;
        let amount = 5_000u64;
        let inputs = sample_public_inputs(threshold, amount, 0, Uuid::new_v4(), Uuid::new_v4());
        let witness = BatchEventWitness::new(0, amount, inputs, threshold).unwrap();

        assert!(witness.is_compliant);
        assert_eq!(witness.event_index, 0);
        assert_eq!(witness.amount, 5000);
    }

    #[test]
    fn test_batch_event_witness_non_compliant() {
        let threshold = 10000u64;
        let amount = 15_000u64;
        let inputs = sample_public_inputs(threshold, amount, 0, Uuid::new_v4(), Uuid::new_v4());
        let witness = BatchEventWitness::new(0, amount, inputs, threshold).unwrap();

        assert!(!witness.is_compliant);
    }

    #[test]
    fn test_batch_event_witness_order_total_cap_boundary() {
        let cap = 10_000u64;
        let mut inputs = sample_public_inputs_with_policy(
            "order_total.cap",
            PolicyParams::cap(cap),
            cap,
            0,
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        // Fill required derived hash
        inputs.policy_hash = compute_policy_hash("order_total.cap", &PolicyParams::cap(cap))
            .unwrap()
            .to_hex();
        let witness = BatchEventWitness::new(0, cap, inputs, cap).unwrap();

        assert!(witness.is_compliant);
    }

    #[test]
    fn test_batch_witness_builder() {
        let threshold = 10000u64;
        let policy_hash = sample_policy_hash(threshold);
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();
        let metadata = BatchMetadata::with_ids(Uuid::new_v4(), tenant_id, store_id, 0, 9);

        let mut builder = BatchWitnessBuilder::new()
            .metadata(metadata)
            .policy_hash(policy_hash)
            .policy_limit(threshold);

        // Add 10 events
        for i in 0..10 {
            let amount = 5_000u64 + i as u64 * 100;
            let inputs = sample_public_inputs(threshold, amount, i, tenant_id, store_id);
            builder = builder.add_event(amount, inputs).unwrap();
        }

        let witness = builder.build().unwrap();

        assert_eq!(witness.num_events(), 10);
        assert!(witness.all_compliant());
    }

    #[test]
    fn test_batch_witness_builder_infers_policy_fields() {
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();
        let metadata = BatchMetadata::with_ids(Uuid::new_v4(), tenant_id, store_id, 0, 0);

        let witness = BatchWitnessBuilder::new()
            .metadata(metadata)
            .add_event(
                1_000,
                sample_public_inputs(10_000u64, 1_000, 0, tenant_id, store_id),
            )
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(witness.policy_limit, 10_000);
        assert_eq!(witness.policy_hash, sample_policy_hash(10_000));
    }

    #[test]
    fn test_batch_witness_builder_rejects_explicit_policy_mismatch() {
        let threshold = 10_000u64;
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();

        let limit_mismatch = BatchWitnessBuilder::new()
            .policy_limit(threshold + 1)
            .add_event(
                1_000,
                sample_public_inputs(threshold, 1_000, 0, tenant_id, store_id),
            );
        assert!(matches!(limit_mismatch, Err(BatchError::InvalidWitness(_))));

        let hash_mismatch = BatchWitnessBuilder::new()
            .policy_hash(sample_policy_hash(threshold + 1))
            .add_event(
                1_000,
                sample_public_inputs(threshold, 1_000, 0, tenant_id, store_id),
            );
        assert!(matches!(hash_mismatch, Err(BatchError::InvalidWitness(_))));
    }

    #[test]
    fn test_batch_witness_builder_rejects_overflow_on_add_event() {
        let threshold = 10_000u64;
        let policy_hash = sample_policy_hash(threshold);
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();
        let mut builder = BatchWitnessBuilder::new()
            .policy_hash(policy_hash)
            .policy_limit(threshold);

        for i in 0..MAX_BATCH_SIZE {
            let amount = 1_000u64;
            builder = builder
                .add_event(
                    amount,
                    sample_public_inputs(threshold, amount, i, tenant_id, store_id),
                )
                .unwrap();
        }

        let result = builder.add_event(
            1_000,
            sample_public_inputs(threshold, 1_000, MAX_BATCH_SIZE, tenant_id, store_id),
        );
        assert!(matches!(result, Err(BatchError::BatchTooLarge { .. })));
    }

    #[test]
    fn test_batch_witness_validation_empty() {
        let threshold = 10000u64;
        let policy_hash = sample_policy_hash(threshold);
        let metadata =
            BatchMetadata::with_ids(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), 0, 0);

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
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();
        let metadata = BatchMetadata::with_ids(Uuid::new_v4(), tenant_id, store_id, 0, 3);

        let mut builder = BatchWitnessBuilder::new()
            .metadata(metadata)
            .policy_hash(policy_hash)
            .policy_limit(threshold);

        for i in 0..4 {
            let amount = 5_000u64;
            let inputs = sample_public_inputs(threshold, amount, i, tenant_id, store_id);
            builder = builder.add_event(5000, inputs).unwrap();
        }

        let witness = builder.build().unwrap();
        let new_root = witness.compute_new_state_root().unwrap();

        // Root should be non-zero
        assert!(new_root.root.iter().any(|f| *f != FELT_ZERO));
    }

    #[test]
    fn test_batch_witness_public_inputs_accumulator() {
        let threshold = 10000u64;
        let policy_hash = sample_policy_hash(threshold);
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();
        let metadata = BatchMetadata::with_ids(Uuid::new_v4(), tenant_id, store_id, 0, 1);

        let input0 = sample_public_inputs(threshold, 5_000, 0, tenant_id, store_id);
        let input1 = sample_public_inputs(threshold, 7_500, 1, tenant_id, store_id);

        let witness = BatchWitnessBuilder::new()
            .metadata(metadata)
            .policy_hash(policy_hash)
            .policy_limit(threshold)
            .add_event(5_000, input0.clone())
            .unwrap()
            .add_event(7_500, input1.clone())
            .unwrap()
            .build()
            .unwrap();

        let gamma = Felt::new(crate::air::trace_layout::MERKLE_LINK_GAMMA);
        let mut expected = [FELT_ZERO; 8];
        for inputs in [&input0, &input1] {
            let hash = hash_to_felts(&inputs.compute_hash().unwrap());
            for i in 0..8 {
                expected[i] = expected[i] * gamma + hash[i];
            }
        }

        assert_eq!(witness.public_inputs_accumulator().unwrap(), expected);
    }

    #[test]
    fn test_batch_witness_policy_mismatch() {
        let threshold = 10_000u64;
        let cap = 10_000u64;
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();
        let metadata = BatchMetadata::with_ids(Uuid::new_v4(), tenant_id, store_id, 0, 0);
        let policy_hash = sample_policy_hash(threshold);

        let wrong_policy_inputs = sample_public_inputs_with_policy(
            "order_total.cap",
            PolicyParams::cap(cap),
            5_000,
            0,
            tenant_id,
            store_id,
        );

        let witness = BatchWitness::new(
            vec![BatchEventWitness::new(0, 5_000, wrong_policy_inputs, threshold).unwrap()],
            metadata,
            BatchStateRoot::genesis(),
            policy_hash,
            threshold,
        );

        assert!(matches!(
            witness.validate(),
            Err(BatchError::InvalidWitness(_))
        ));
    }

    #[test]
    fn test_batch_witness_witness_commitment_binding() {
        let threshold = 10_000u64;
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();
        let metadata = BatchMetadata::with_ids(Uuid::new_v4(), tenant_id, store_id, 0, 0);
        let policy_hash = sample_policy_hash(threshold);

        let mut inputs = sample_public_inputs(threshold, 5_000, 0, tenant_id, store_id);
        let amount = 5_000u64;
        let amount_limbs = BatchEventWitness::new(0, amount, inputs.clone(), threshold)
            .unwrap()
            .amount_limbs();
        let actual_commitment = compute_amount_commitment_u64(&amount_limbs);
        inputs.witness_commitment = Some(witness_commitment_u64_to_hex(&actual_commitment));

        let witness = BatchWitness::new(
            vec![BatchEventWitness::new(0, amount, inputs, threshold).unwrap()],
            metadata,
            BatchStateRoot::genesis(),
            policy_hash,
            threshold,
        );

        assert!(witness.validate().is_ok());

        let bad_tenant_id = Uuid::new_v4();
        let bad_store_id = Uuid::new_v4();
        let mut bad_inputs =
            sample_public_inputs(threshold, amount, 0, bad_tenant_id, bad_store_id);
        bad_inputs.witness_commitment = Some("0".repeat(64));
        let bad_witness = BatchWitness::new(
            vec![BatchEventWitness::new(0, amount, bad_inputs, threshold).unwrap()],
            BatchMetadata::with_ids(Uuid::new_v4(), bad_tenant_id, bad_store_id, 0, 0),
            BatchStateRoot::genesis(),
            policy_hash,
            threshold,
        );

        assert!(matches!(
            bad_witness.validate(),
            Err(BatchError::InvalidWitness(_))
        ));
    }

    #[test]
    fn test_batch_witness_missing_witness_commitment() {
        let threshold = 10_000u64;
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();
        let metadata = BatchMetadata::with_ids(Uuid::new_v4(), tenant_id, store_id, 0, 0);
        let policy_hash = sample_policy_hash(threshold);
        let mut inputs = sample_public_inputs(threshold, 5_000, 0, tenant_id, store_id);
        inputs.witness_commitment = None;

        let witness = BatchWitness::new(
            vec![BatchEventWitness::new(0, 5_000, inputs, threshold).unwrap()],
            metadata,
            BatchStateRoot::genesis(),
            policy_hash,
            threshold,
        );

        assert!(matches!(
            witness.validate(),
            Err(BatchError::InvalidWitness(_))
        ));
    }

    #[test]
    fn test_batch_witness_rejects_duplicate_event_ids() {
        let threshold = 10_000u64;
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();
        let shared_event_id = Uuid::new_v4();
        let metadata = BatchMetadata::with_ids(Uuid::new_v4(), tenant_id, store_id, 0, 1);
        let policy_hash = sample_policy_hash(threshold);

        let mut first = sample_public_inputs(threshold, 5_000, 0, tenant_id, store_id);
        let mut second = sample_public_inputs(threshold, 2_500, 1, tenant_id, store_id);
        first.event_id = shared_event_id;
        second.event_id = shared_event_id;

        let witness = BatchWitness::new(
            vec![
                BatchEventWitness::new(0, 5_000, first, threshold).unwrap(),
                BatchEventWitness::new(1, 2_500, second, threshold).unwrap(),
            ],
            metadata,
            BatchStateRoot::genesis(),
            policy_hash,
            threshold,
        );

        assert!(matches!(
            witness.validate(),
            Err(BatchError::InvalidWitness(_))
        ));
    }

    #[test]
    fn test_batch_witness_tenant_store_mismatch() {
        let threshold = 10_000u64;
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();
        let metadata = BatchMetadata::with_ids(Uuid::new_v4(), tenant_id, store_id, 0, 0);
        let policy_hash = sample_policy_hash(threshold);

        let mut inputs = sample_public_inputs(threshold, 5_000, 0, tenant_id, store_id);
        inputs.tenant_id = Uuid::new_v4(); // Intentionally mismatch
        let witness = BatchWitness::new(
            vec![BatchEventWitness::new(0, 5_000, inputs, threshold).unwrap()],
            metadata,
            BatchStateRoot::genesis(),
            policy_hash,
            threshold,
        );

        assert!(matches!(
            witness.validate(),
            Err(BatchError::InvalidWitness(_))
        ));
    }
}
