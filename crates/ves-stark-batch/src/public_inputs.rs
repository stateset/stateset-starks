//! Batch public inputs
//!
//! This module defines the public inputs for batch state transition proofs.

use ves_stark_primitives::{felt_from_u64, Felt, FELT_ONE, FELT_ZERO};
use winter_math::ToElements;

/// Public inputs for a batch state transition proof
#[derive(Debug, Clone)]
pub struct BatchPublicInputs {
    /// Previous batch state root (4 field elements)
    pub prev_state_root: [Felt; 4],

    /// New batch state root (4 field elements)
    pub new_state_root: [Felt; 4],

    /// Batch ID (4 field elements from UUID)
    pub batch_id: [Felt; 4],

    /// Tenant ID (4 field elements from UUID)
    pub tenant_id: [Felt; 4],

    /// Store ID (4 field elements from UUID)
    pub store_id: [Felt; 4],

    /// First sequence number in batch
    pub sequence_start: Felt,

    /// Last sequence number in batch
    pub sequence_end: Felt,

    /// Number of events in batch
    pub num_events: Felt,

    /// All events compliant flag (1 if all pass, 0 otherwise)
    pub all_compliant: Felt,

    /// Policy hash (8 field elements from SHA-256)
    pub policy_hash: [Felt; 8],

    /// Policy limit (threshold or cap)
    pub policy_limit: Felt,
}

impl BatchPublicInputs {
    /// Create new batch public inputs
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        prev_state_root: [Felt; 4],
        new_state_root: [Felt; 4],
        batch_id: [Felt; 4],
        tenant_id: [Felt; 4],
        store_id: [Felt; 4],
        sequence_start: u64,
        sequence_end: u64,
        num_events: usize,
        all_compliant: bool,
        policy_hash: [Felt; 8],
        policy_limit: u64,
    ) -> Self {
        Self {
            prev_state_root,
            new_state_root,
            batch_id,
            tenant_id,
            store_id,
            sequence_start: felt_from_u64(sequence_start),
            sequence_end: felt_from_u64(sequence_end),
            num_events: felt_from_u64(num_events as u64),
            all_compliant: if all_compliant { FELT_ONE } else { FELT_ZERO },
            policy_hash,
            policy_limit: felt_from_u64(policy_limit),
        }
    }

    /// Create batch public inputs for genesis (first batch)
    pub fn genesis(
        new_state_root: [Felt; 4],
        batch_id: [Felt; 4],
        tenant_id: [Felt; 4],
        store_id: [Felt; 4],
        num_events: usize,
        policy_hash: [Felt; 8],
        policy_limit: u64,
    ) -> Self {
        Self::new(
            [FELT_ZERO; 4], // Genesis has zero prev_state_root
            new_state_root,
            batch_id,
            tenant_id,
            store_id,
            0,
            (num_events - 1) as u64,
            num_events,
            true,
            policy_hash,
            policy_limit,
        )
    }

    /// Get the number of events as usize
    pub fn num_events_usize(&self) -> usize {
        self.num_events.as_int() as usize
    }

    /// Check if all events were compliant
    pub fn is_all_compliant(&self) -> bool {
        self.all_compliant == FELT_ONE
    }

    /// Get policy limit as u64
    pub fn policy_limit_u64(&self) -> u64 {
        self.policy_limit.as_int()
    }
}

impl Default for BatchPublicInputs {
    fn default() -> Self {
        Self {
            prev_state_root: [FELT_ZERO; 4],
            new_state_root: [FELT_ZERO; 4],
            batch_id: [FELT_ZERO; 4],
            tenant_id: [FELT_ZERO; 4],
            store_id: [FELT_ZERO; 4],
            sequence_start: FELT_ZERO,
            sequence_end: FELT_ZERO,
            num_events: FELT_ZERO,
            all_compliant: FELT_ONE,
            policy_hash: [FELT_ZERO; 8],
            policy_limit: FELT_ZERO,
        }
    }
}

impl ToElements<Felt> for BatchPublicInputs {
    fn to_elements(&self) -> Vec<Felt> {
        let mut elements = Vec::with_capacity(40);

        // State roots (8 elements)
        elements.extend_from_slice(&self.prev_state_root);
        elements.extend_from_slice(&self.new_state_root);

        // IDs (12 elements)
        elements.extend_from_slice(&self.batch_id);
        elements.extend_from_slice(&self.tenant_id);
        elements.extend_from_slice(&self.store_id);

        // Sequence info (3 elements)
        elements.push(self.sequence_start);
        elements.push(self.sequence_end);
        elements.push(self.num_events);

        // Compliance (1 element)
        elements.push(self.all_compliant);

        // Policy (9 elements)
        elements.extend_from_slice(&self.policy_hash);
        elements.push(self.policy_limit);

        elements
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_public_inputs() {
        let inputs = BatchPublicInputs::default();
        assert_eq!(inputs.prev_state_root, [FELT_ZERO; 4]);
        assert!(inputs.is_all_compliant());
    }

    #[test]
    fn test_to_elements() {
        let inputs = BatchPublicInputs::default();
        let elements = inputs.to_elements();

        // Should have correct number of elements
        assert_eq!(elements.len(), 33); // 4+4+4+4+4+1+1+1+1+8+1 = 33
    }

    #[test]
    fn test_genesis_inputs() {
        let inputs = BatchPublicInputs::genesis(
            [felt_from_u64(1); 4],
            [felt_from_u64(2); 4],
            [felt_from_u64(3); 4],
            [felt_from_u64(4); 4],
            10,
            [felt_from_u64(5); 8],
            10000,
        );

        assert_eq!(inputs.prev_state_root, [FELT_ZERO; 4]);
        assert_eq!(inputs.num_events_usize(), 10);
        assert!(inputs.is_all_compliant());
    }
}
