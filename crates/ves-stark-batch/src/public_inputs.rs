//! Batch public inputs
//!
//! This module defines the public inputs for batch state transition proofs.

use ves_stark_primitives::{
    compute_policy_hash, felt_from_u64, hash_to_felts,
    public_inputs::{CompliancePublicInputs, PolicyParams},
    Felt, FELT_ONE, FELT_ZERO,
};
use winter_math::ToElements;

use crate::air::trace_layout::MAX_BATCH_SIZE;
use crate::error::{BatchError, BatchResult};
use crate::state::BatchMetadata;

/// Supported batch policy kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum BatchPolicyKind {
    /// `aml.threshold`: prove `amount < threshold`.
    AmlThreshold = 0,
    /// `order_total.cap`: prove `amount <= cap`.
    OrderTotalCap = 1,
}

impl BatchPolicyKind {
    /// Convert to field element.
    pub fn to_felt(self) -> Felt {
        felt_from_u64(self as u64)
    }

    /// Convert from field element.
    pub fn from_felt(felt: Felt) -> Option<Self> {
        Self::from_u64(felt.as_int())
    }

    /// Convert from raw integer encoding.
    pub fn from_u64(value: u64) -> Option<Self> {
        match value {
            0 => Some(Self::AmlThreshold),
            1 => Some(Self::OrderTotalCap),
            _ => None,
        }
    }

    /// Convert from canonical policy identifier.
    pub fn from_policy_id(policy_id: &str) -> Option<Self> {
        match policy_id {
            "aml.threshold" => Some(Self::AmlThreshold),
            "order_total.cap" => Some(Self::OrderTotalCap),
            _ => None,
        }
    }

    /// Canonical policy identifier.
    pub fn policy_id(self) -> &'static str {
        match self {
            Self::AmlThreshold => "aml.threshold",
            Self::OrderTotalCap => "order_total.cap",
        }
    }

    /// Canonical policy parameters for this policy kind and limit.
    pub fn policy_params(self, policy_limit: u64) -> PolicyParams {
        match self {
            Self::AmlThreshold => PolicyParams::threshold(policy_limit),
            Self::OrderTotalCap => PolicyParams::cap(policy_limit),
        }
    }

    fn try_policy_hash_with_error<F>(self, policy_limit: u64, error: F) -> BatchResult<[Felt; 8]>
    where
        F: Fn(String) -> BatchError,
    {
        let hash = compute_policy_hash(self.policy_id(), &self.policy_params(policy_limit))
            .map_err(|err| error(format!("failed to compute canonical policy hash: {err}")))?;
        Ok(hash_to_felts(&hash))
    }

    /// Compute the canonical policy hash committed into Merkle leaves.
    pub fn try_policy_hash(self, policy_limit: u64) -> BatchResult<[Felt; 8]> {
        self.try_policy_hash_with_error(policy_limit, BatchError::InvalidPublicInputs)
    }
}

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

    /// Batch timestamp (Unix epoch seconds)
    pub timestamp: Felt,

    /// Number of events in batch
    pub num_events: Felt,

    /// All events compliant flag (1 if all pass, 0 otherwise)
    pub all_compliant: Felt,

    /// Policy kind (`aml.threshold` or `order_total.cap`)
    pub policy_kind: Felt,

    /// Policy limit (threshold or cap)
    pub policy_limit: Felt,

    /// Ordered accumulator over canonical per-event public-input hashes.
    pub public_inputs_accumulator: [Felt; 8],
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
        timestamp: u64,
        num_events: usize,
        all_compliant: bool,
        policy_kind: BatchPolicyKind,
        policy_limit: u64,
        public_inputs_accumulator: [Felt; 8],
    ) -> Self {
        Self {
            prev_state_root,
            new_state_root,
            batch_id,
            tenant_id,
            store_id,
            sequence_start: felt_from_u64(sequence_start),
            sequence_end: felt_from_u64(sequence_end),
            timestamp: felt_from_u64(timestamp),
            num_events: felt_from_u64(num_events as u64),
            all_compliant: if all_compliant { FELT_ONE } else { FELT_ZERO },
            policy_kind: policy_kind.to_felt(),
            policy_limit: felt_from_u64(policy_limit),
            public_inputs_accumulator,
        }
    }

    /// Create batch public inputs for genesis (first batch)
    pub fn genesis(
        new_state_root: [Felt; 4],
        batch_id: [Felt; 4],
        tenant_id: [Felt; 4],
        store_id: [Felt; 4],
        num_events: usize,
        policy_kind: BatchPolicyKind,
        policy_limit: u64,
    ) -> Self {
        let sequence_end = num_events.saturating_sub(1) as u64;
        Self::new(
            [FELT_ZERO; 4], // Genesis has zero prev_state_root
            new_state_root,
            batch_id,
            tenant_id,
            store_id,
            0,
            sequence_end,
            0,
            num_events,
            true,
            policy_kind,
            policy_limit,
            [FELT_ZERO; 8],
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

    /// Get the policy kind.
    pub fn policy_kind_enum(&self) -> Option<BatchPolicyKind> {
        BatchPolicyKind::from_felt(self.policy_kind)
    }

    /// Compute the canonical policy hash from the public policy kind and limit.
    pub fn try_policy_hash(&self) -> BatchResult<[Felt; 8]> {
        self.try_policy_hash_with_error(BatchError::InvalidPublicInputs)
    }

    fn try_policy_hash_with_error<F>(&self, error: F) -> BatchResult<[Felt; 8]>
    where
        F: Fn(String) -> BatchError + Copy,
    {
        self.policy_kind_enum()
            .ok_or_else(|| error("unsupported policy_kind".to_string()))?
            .try_policy_hash_with_error(self.policy_limit_u64(), error)
    }

    /// Compute the canonical policy hash from the public policy kind and limit,
    /// falling back to zero for malformed direct AIR callers.
    pub fn policy_hash_or_zero(&self) -> [Felt; 8] {
        self.try_policy_hash().unwrap_or([FELT_ZERO; 8])
    }

    /// Compute the chained Rescue metadata hash from public metadata fields.
    ///
    /// The previous state root is mixed into this hash so the batch's
    /// `new_state_root` is bound to the claimed predecessor.
    pub fn metadata_hash(&self) -> [Felt; 4] {
        BatchMetadata::chained_rescue_hash_from_parts(
            &self.prev_state_root,
            &self.batch_id,
            &self.tenant_id,
            &self.store_id,
            self.sequence_start,
            self.sequence_end,
            self.timestamp,
        )
    }

    /// Get policy limit as u64
    pub fn policy_limit_u64(&self) -> u64 {
        self.policy_limit.as_int()
    }

    fn validate_with_error<F>(&self, error: F) -> BatchResult<usize>
    where
        F: Fn(String) -> BatchError + Copy,
    {
        if self.all_compliant != FELT_ZERO && self.all_compliant != FELT_ONE {
            return Err(error("all_compliant must be 0 or 1".to_string()));
        }

        self.try_policy_hash_with_error(error)?;

        let sequence_start = self.sequence_start.as_int();
        let sequence_end = self.sequence_end.as_int();
        if sequence_start > sequence_end {
            return Err(error("sequence_start must be <= sequence_end".to_string()));
        }

        let num_events_u64 = self.num_events.as_int();
        if num_events_u64 == 0 {
            if sequence_start != 0 || sequence_end != 0 {
                return Err(error(
                    "zero-event batches must use sequence_start = sequence_end = 0".to_string(),
                ));
            }
            return usize::try_from(num_events_u64)
                .map_err(|_| error("num_events does not fit in platform usize".to_string()));
        }

        if num_events_u64 > MAX_BATCH_SIZE as u64 {
            return Err(error(format!(
                "batch size {} exceeds maximum {}",
                num_events_u64, MAX_BATCH_SIZE
            )));
        }

        let expected_num_events = sequence_end
            .checked_sub(sequence_start)
            .and_then(|span| span.checked_add(1))
            .ok_or_else(|| error("sequence span overflows u64".to_string()))?;
        if expected_num_events != num_events_u64 {
            return Err(error(format!(
                "inconsistent public inputs: expected {} events from sequence range, got {}",
                expected_num_events, num_events_u64
            )));
        }

        usize::try_from(num_events_u64)
            .map_err(|_| error("num_events does not fit in platform usize".to_string()))
    }

    /// Validate public-input structure for proof generation / verification.
    pub fn validate(&self) -> BatchResult<usize> {
        self.validate_with_error(BatchError::InvalidPublicInputs)
    }

    pub(crate) fn validate_for_deserialization(&self) -> BatchResult<usize> {
        self.validate_with_error(BatchError::DeserializationFailed)
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
            timestamp: FELT_ZERO,
            num_events: FELT_ZERO,
            all_compliant: FELT_ONE,
            policy_kind: BatchPolicyKind::AmlThreshold.to_felt(),
            policy_limit: FELT_ZERO,
            public_inputs_accumulator: [FELT_ZERO; 8],
        }
    }
}

impl ToElements<Felt> for BatchPublicInputs {
    fn to_elements(&self) -> Vec<Felt> {
        let mut elements = Vec::with_capacity(35);

        // State roots (8 elements)
        elements.extend_from_slice(&self.prev_state_root);
        elements.extend_from_slice(&self.new_state_root);

        // IDs (12 elements)
        elements.extend_from_slice(&self.batch_id);
        elements.extend_from_slice(&self.tenant_id);
        elements.extend_from_slice(&self.store_id);

        // Sequence info (4 elements)
        elements.push(self.sequence_start);
        elements.push(self.sequence_end);
        elements.push(self.timestamp);
        elements.push(self.num_events);

        // Compliance (1 element)
        elements.push(self.all_compliant);

        // Policy (2 elements)
        elements.push(self.policy_kind);
        elements.push(self.policy_limit);

        // Canonical event public-input stream accumulator (8 elements)
        elements.extend_from_slice(&self.public_inputs_accumulator);

        elements
    }
}

/// Compute the ordered accumulator over witness-bound per-event public-input hashes.
pub fn compute_public_inputs_accumulator(
    public_inputs: &[CompliancePublicInputs],
) -> BatchResult<[Felt; 8]> {
    let gamma = Felt::new(crate::air::trace_layout::MERKLE_LINK_GAMMA);
    let mut acc = [FELT_ZERO; 8];

    for (event_index, inputs) in public_inputs.iter().enumerate() {
        let public_inputs_hash = inputs
            .compute_bound_hash()
            .map(|hash| hash_to_felts(&hash))
            .map_err(|err| {
                BatchError::InvalidPublicInputs(format!(
                    "event {event_index} bound public-input hash computation failed: {err}"
                ))
            })?;
        for i in 0..8 {
            acc[i] = acc[i] * gamma + public_inputs_hash[i];
        }
    }

    Ok(acc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use ves_stark_primitives::public_inputs::witness_commitment_u64_to_hex;

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
        assert_eq!(elements.len(), 35);
    }

    #[test]
    fn test_genesis_inputs() {
        let inputs = BatchPublicInputs::genesis(
            [felt_from_u64(1); 4],
            [felt_from_u64(2); 4],
            [felt_from_u64(3); 4],
            [felt_from_u64(4); 4],
            10,
            BatchPolicyKind::AmlThreshold,
            10000,
        );

        assert_eq!(inputs.prev_state_root, [FELT_ZERO; 4]);
        assert_eq!(inputs.num_events_usize(), 10);
        assert!(inputs.is_all_compliant());
        assert_eq!(inputs.timestamp, FELT_ZERO);
        assert_eq!(
            inputs.policy_kind_enum(),
            Some(BatchPolicyKind::AmlThreshold)
        );
    }

    #[test]
    fn test_validate_rejects_batch_larger_than_maximum() {
        let inputs = BatchPublicInputs::new(
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
            [FELT_ZERO; 8],
        );

        let err = inputs
            .validate()
            .expect_err("oversized batch should be rejected");
        assert!(matches!(err, BatchError::InvalidPublicInputs(_)));
    }

    #[test]
    fn test_genesis_inputs_zero_events() {
        let inputs = BatchPublicInputs::genesis(
            [felt_from_u64(1); 4],
            [felt_from_u64(2); 4],
            [felt_from_u64(3); 4],
            [felt_from_u64(4); 4],
            0,
            BatchPolicyKind::AmlThreshold,
            10000,
        );

        assert_eq!(inputs.num_events_usize(), 0);
        assert_eq!(inputs.sequence_end.as_int(), 0);
        assert_eq!(inputs.timestamp, FELT_ZERO);
        assert_eq!(inputs.validate().unwrap(), 0);
    }

    #[test]
    fn test_policy_hash_derivation() {
        let inputs = BatchPublicInputs::new(
            [FELT_ZERO; 4],
            [FELT_ZERO; 4],
            [FELT_ZERO; 4],
            [FELT_ZERO; 4],
            [FELT_ZERO; 4],
            0,
            0,
            0,
            1,
            true,
            BatchPolicyKind::OrderTotalCap,
            10_000,
            [felt_from_u64(7); 8],
        );

        let expected_hash = BatchPolicyKind::OrderTotalCap
            .try_policy_hash(10_000)
            .unwrap();
        assert_eq!(inputs.try_policy_hash().unwrap(), expected_hash);
        assert_eq!(inputs.public_inputs_accumulator, [felt_from_u64(7); 8]);
    }

    #[test]
    fn test_metadata_hash_depends_on_prev_state_root() {
        let inputs_a = BatchPublicInputs::new(
            [felt_from_u64(1); 4],
            [FELT_ZERO; 4],
            [felt_from_u64(2); 4],
            [felt_from_u64(3); 4],
            [felt_from_u64(4); 4],
            0,
            0,
            123,
            1,
            true,
            BatchPolicyKind::AmlThreshold,
            10_000,
            [FELT_ZERO; 8],
        );
        let inputs_b = BatchPublicInputs {
            prev_state_root: [felt_from_u64(9); 4],
            ..inputs_a.clone()
        };

        assert_ne!(inputs_a.metadata_hash(), inputs_b.metadata_hash());
    }

    #[test]
    fn test_compute_public_inputs_accumulator() {
        let witness_commitment = witness_commitment_u64_to_hex(&[1, 2, 3, 4]);
        let inputs0 = CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            sequence_number: 0,
            payload_kind: 1,
            payload_plain_hash: "11".repeat(32),
            payload_cipher_hash: "22".repeat(32),
            event_signing_hash: "33".repeat(32),
            policy_id: "aml.threshold".to_string(),
            policy_params: PolicyParams::threshold(10_000),
            policy_hash: compute_policy_hash("aml.threshold", &PolicyParams::threshold(10_000))
                .unwrap()
                .to_hex(),
            witness_commitment: Some(witness_commitment.clone()),
            authorization_receipt_hash: None,
            amount_binding_hash: None,
        };
        let inputs1 = CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id: inputs0.tenant_id,
            store_id: inputs0.store_id,
            sequence_number: 1,
            payload_kind: 1,
            payload_plain_hash: "44".repeat(32),
            payload_cipher_hash: "55".repeat(32),
            event_signing_hash: "66".repeat(32),
            policy_id: "aml.threshold".to_string(),
            policy_params: PolicyParams::threshold(10_000),
            policy_hash: inputs0.policy_hash.clone(),
            witness_commitment: Some(witness_commitment),
            authorization_receipt_hash: None,
            amount_binding_hash: None,
        };

        let gamma = Felt::new(crate::air::trace_layout::MERKLE_LINK_GAMMA);
        let mut expected = [FELT_ZERO; 8];
        for inputs in [&inputs0, &inputs1] {
            let hash = hash_to_felts(&inputs.compute_bound_hash().unwrap());
            for i in 0..8 {
                expected[i] = expected[i] * gamma + hash[i];
            }
        }

        assert_eq!(
            compute_public_inputs_accumulator(&[inputs0, inputs1]).unwrap(),
            expected
        );
    }

    #[test]
    fn test_validate_rejects_invalid_policy_kind() {
        let inputs = BatchPublicInputs {
            policy_kind: felt_from_u64(99),
            ..Default::default()
        };

        assert!(matches!(
            inputs.validate(),
            Err(BatchError::InvalidPublicInputs(_))
        ));
    }

    #[test]
    fn test_policy_hash_or_zero_for_invalid_policy_kind() {
        let inputs = BatchPublicInputs {
            policy_kind: felt_from_u64(99),
            ..Default::default()
        };

        assert_eq!(inputs.policy_hash_or_zero(), [FELT_ZERO; 8]);
    }
}
