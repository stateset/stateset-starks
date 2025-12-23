//! Execution trace construction for VES compliance proofs
//!
//! This module builds the execution trace that satisfies the AIR constraints.
//! The trace is a 2D matrix of field elements where each row represents a
//! step in the computation.

use ves_stark_air::trace::{cols, phases, TRACE_WIDTH, MIN_TRACE_LENGTH};
use ves_stark_air::policies::aml_threshold::AmlThresholdPolicy;
use ves_stark_primitives::{Felt, felt_from_u64, FELT_ZERO, FELT_ONE};
use ves_stark_primitives::rescue::{rescue_permutation_trace, STATE_WIDTH as RESCUE_STATE_WIDTH};
use crate::witness::ComplianceWitness;
use crate::policy::Policy;
use crate::error::ProverError;
use winter_prover::TraceTable;

/// Decompose a field element (representing a u32 limb) into 32 bits
/// Returns bits in little-endian order: bit[0] is LSB, bit[31] is MSB
fn decompose_to_bits(limb: Felt) -> [Felt; 32] {
    let mut bits = [FELT_ZERO; 32];
    let value = limb.as_int() as u32;

    for i in 0..32 {
        if (value >> i) & 1 == 1 {
            bits[i] = FELT_ONE;
        }
    }

    bits
}

/// Compute subtraction witness for 64-bit comparison.
///
/// Returns (diff, borrow) where diff is a 2-limb u32 subtraction witness and
/// borrow[0] is the borrow from limb 0 to limb 1, borrow[1] is the final borrow.
fn compute_subtraction_witness(
    amount_limbs: &[Felt; 8],
    limit_limbs: &[Felt; 8],
) -> Result<([Felt; 8], [Felt; 8]), ProverError> {
    let a0 = amount_limbs[0].as_int();
    let a1 = amount_limbs[1].as_int();
    let t0 = limit_limbs[0].as_int();
    let t1 = limit_limbs[1].as_int();

    let (diff0, borrow0) = if a0 <= t0 {
        (t0 - a0, 0u64)
    } else {
        (t0 + (1u64 << 32) - a0, 1u64)
    };

    let a1_with_borrow = a1 + borrow0;
    let (diff1, borrow1) = if a1_with_borrow <= t1 {
        (t1 - a1_with_borrow, 0u64)
    } else {
        (t1 + (1u64 << 32) - a1_with_borrow, 1u64)
    };

    if borrow1 != 0 {
        return Err(ProverError::constraint_violation(
            "Amount exceeds limit in subtraction witness",
        ));
    }

    let mut diff = [FELT_ZERO; 8];
    diff[0] = felt_from_u64(diff0);
    diff[1] = felt_from_u64(diff1);

    let mut borrow = [FELT_ZERO; 8];
    borrow[0] = felt_from_u64(borrow0);
    borrow[1] = felt_from_u64(borrow1);

    Ok((diff, borrow))
}


/// Build the execution trace for a compliance proof
pub struct TraceBuilder {
    /// The witness data
    witness: ComplianceWitness,

    /// The policy being proven
    policy: Policy,

    /// Trace length (must be power of 2)
    trace_length: usize,
}

impl TraceBuilder {
    /// Create a new trace builder with unified policy
    pub fn new(witness: ComplianceWitness, policy: Policy) -> Self {
        Self {
            witness,
            policy,
            trace_length: MIN_TRACE_LENGTH,
        }
    }

    /// Create a new trace builder from an AmlThresholdPolicy
    pub fn from_aml_threshold(witness: ComplianceWitness, policy: AmlThresholdPolicy) -> Self {
        Self::new(witness, policy.into())
    }

    /// Set the trace length
    pub fn with_trace_length(mut self, length: usize) -> Self {
        self.trace_length = length.next_power_of_two().max(MIN_TRACE_LENGTH);
        self
    }

    /// Build the execution trace
    pub fn build(self) -> Result<TraceTable<Felt>, ProverError> {
        // Validate witness against the policy
        if !self.policy.validate_amount(self.witness.amount) {
            return Err(ProverError::policy_validation_failed(format!(
                "Amount {} does not satisfy policy {} with limit {}",
                self.witness.amount,
                self.policy.policy_id(),
                self.policy.limit()
            )));
        }

        // Validate public inputs policy hash + match policy parameters
        let policy_hash_valid = self.witness
            .public_inputs
            .validate_policy_hash()
            .map_err(|e| ProverError::InvalidPublicInputs(format!("{e}")))?;
        if !policy_hash_valid {
            return Err(ProverError::InvalidPublicInputs(
                "Policy hash mismatch".to_string(),
            ));
        }
        let inputs_policy = Policy::from_public_inputs(
            &self.witness.public_inputs.policy_id,
            &self.witness.public_inputs.policy_params,
        )
        .map_err(|e| ProverError::InvalidPublicInputs(format!("Invalid policy params: {e}")))?;
        if inputs_policy != self.policy {
            return Err(ProverError::InvalidPublicInputs(format!(
                "Policy mismatch: public inputs are for {}, trace built for {}",
                inputs_policy.policy_id(),
                self.policy.policy_id()
            )));
        }

        // Initialize trace columns
        let mut trace = vec![vec![FELT_ZERO; self.trace_length]; TRACE_WIDTH];

        // Get limb representations
        let amount_limbs = self.witness.amount_limbs();
        let limit_limbs = self
            .policy
            .effective_limit_limbs()
            .map_err(|e| ProverError::policy_validation_failed(format!("{e}")))?;

        // Compute bit decomposition for amount limbs 0-1 only
        // Limbs 2-7 are boundary-asserted to zero, no decomposition needed
        let limb0_bits = decompose_to_bits(amount_limbs[0]);
        let limb1_bits = decompose_to_bits(amount_limbs[1]);

        // Compute subtraction witness for amount <= limit
        let (diff, borrow) = compute_subtraction_witness(&amount_limbs, &limit_limbs)?;
        let diff0_bits = decompose_to_bits(diff[0]);
        let diff1_bits = decompose_to_bits(diff[1]);

        // Build initial Rescue state (after absorption, before permutation)
        let mut rescue_init_state = [FELT_ZERO; RESCUE_STATE_WIDTH];
        rescue_init_state[..8].copy_from_slice(&amount_limbs);
        rescue_init_state[8] = felt_from_u64(8);
        let rescue_states = rescue_permutation_trace(&rescue_init_state);
        let rescue_final = rescue_states
            .last()
            .ok_or_else(|| ProverError::TraceGenerationError("Rescue trace missing".to_string()))?;

        // Convert public inputs to field elements and bind into trace columns
        let pub_inputs_felts = self.witness
            .public_inputs
            .to_field_elements()
            .map_err(|e| ProverError::InvalidPublicInputs(format!("{e}")))?;
        let pub_inputs_vec = pub_inputs_felts.to_vec();
        if pub_inputs_vec.len() != cols::PUBLIC_INPUTS_LEN {
            return Err(ProverError::InvalidPublicInputs(format!(
                "Expected {} public input elements, got {}",
                cols::PUBLIC_INPUTS_LEN,
                pub_inputs_vec.len()
            )));
        }

        // Fill the trace
        for row in 0..self.trace_length {
            // Set Rescue state columns (permutation trace for first 15 rows, then constant)
            let rescue_state = if row < rescue_states.len() {
                rescue_states[row]
            } else {
                *rescue_final
            };
            for i in 0..RESCUE_STATE_WIDTH {
                trace[cols::RESCUE_STATE_START + i][row] = rescue_state[i];
            }
            // Set amount limbs (constant throughout trace for this simple AIR)
            for i in 0..8 {
                trace[cols::AMOUNT_START + i][row] = amount_limbs[i];
            }

            // Set threshold/cap limbs (constant throughout trace)
            for i in 0..8 {
                trace[cols::THRESHOLD_START + i][row] = limit_limbs[i];
            }

            // Set legacy comparison columns to zero (unused in V3)
            for i in 0..8 {
                trace[cols::COMPARISON_START + i][row] = FELT_ZERO;
            }

            // Set bit decomposition for limb 0 (constant throughout trace)
            for i in 0..32 {
                trace[cols::AMOUNT_BITS_LIMB0_START + i][row] = limb0_bits[i];
            }

            // Set bit decomposition for limb 1 (constant throughout trace)
            for i in 0..32 {
                trace[cols::AMOUNT_BITS_LIMB1_START + i][row] = limb1_bits[i];
            }

            // Note: Limbs 2-7 are boundary-asserted to zero, no bit decomposition needed

            // Set subtraction witness columns
            for i in 0..8 {
                trace[cols::diff(i)][row] = diff[i];
                trace[cols::borrow(i)][row] = borrow[i];
                trace[cols::is_less(i)][row] = FELT_ZERO;
                trace[cols::is_equal(i)][row] = FELT_ZERO;
            }

            // Set diff bit decomposition for limb 0
            for i in 0..32 {
                trace[cols::DIFF_BITS_LIMB0_START + i][row] = diff0_bits[i];
            }

            // Set diff bit decomposition for limb 1
            for i in 0..32 {
                trace[cols::DIFF_BITS_LIMB1_START + i][row] = diff1_bits[i];
            }

            // Bind public inputs into trace columns
            for (idx, val) in pub_inputs_vec.iter().enumerate() {
                trace[cols::public_input(idx)][row] = *val;
            }

            // Set control flags
            trace[cols::FLAG_IS_FIRST][row] = if row == 0 { FELT_ONE } else { FELT_ZERO };
            trace[cols::FLAG_IS_LAST][row] = if row == self.trace_length - 1 { FELT_ONE } else { FELT_ZERO };
            trace[cols::ROUND_COUNTER][row] = felt_from_u64(row as u64);
            trace[cols::PHASE][row] = if row < rescue_states.len() {
                felt_from_u64(phases::RESCUE_HASH)
            } else {
                felt_from_u64(phases::COMPARISON)
            };
        }

        Ok(TraceTable::init(trace))
    }
}

/// Trace information for the prover
#[derive(Debug, Clone)]
pub struct TraceInfo {
    /// Width of the trace
    pub width: usize,
    /// Length of the trace (power of 2)
    pub length: usize,
}

impl TraceInfo {
    /// Create new trace info
    pub fn new(length: usize) -> Self {
        Self {
            width: TRACE_WIDTH,
            length: length.next_power_of_two().max(MIN_TRACE_LENGTH),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ves_stark_primitives::public_inputs::{CompliancePublicInputs, PolicyParams, compute_policy_hash};
    use uuid::Uuid;
    use winter_prover::Trace;

    fn sample_inputs_aml(threshold: u64) -> CompliancePublicInputs {
        let policy_id = "aml.threshold";
        let params = PolicyParams::threshold(threshold);
        let hash = compute_policy_hash(policy_id, &params).unwrap();

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

    fn sample_inputs_cap(cap: u64) -> CompliancePublicInputs {
        let policy_id = "order_total.cap";
        let params = PolicyParams::cap(cap);
        let hash = compute_policy_hash(policy_id, &params).unwrap();

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
    fn test_trace_builder_aml_valid() {
        let threshold = 10000u64;
        let inputs = sample_inputs_aml(threshold);
        let witness = ComplianceWitness::new(5000, inputs);
        let policy = Policy::aml_threshold(threshold);

        let builder = TraceBuilder::new(witness, policy);
        let trace = builder.build();

        assert!(trace.is_ok());
        let trace = trace.unwrap();
        assert_eq!(trace.width(), TRACE_WIDTH);
        assert_eq!(trace.length(), MIN_TRACE_LENGTH);
    }

    #[test]
    fn test_trace_builder_aml_invalid() {
        let threshold = 10000u64;
        let inputs = sample_inputs_aml(threshold);
        let witness = ComplianceWitness::new(15000, inputs);
        let policy = Policy::aml_threshold(threshold);

        let builder = TraceBuilder::new(witness, policy);
        let trace = builder.build();

        assert!(trace.is_err());
    }

    #[test]
    fn test_trace_builder_aml_boundary() {
        // For AML threshold, amount == threshold should fail (must be strictly less)
        let threshold = 10000u64;
        let inputs = sample_inputs_aml(threshold);
        let witness = ComplianceWitness::new(10000, inputs);
        let policy = Policy::aml_threshold(threshold);

        let builder = TraceBuilder::new(witness, policy);
        let trace = builder.build();

        assert!(trace.is_err());
    }

    #[test]
    fn test_trace_builder_cap_valid() {
        let cap = 10000u64;
        let inputs = sample_inputs_cap(cap);
        let witness = ComplianceWitness::new(5000, inputs);
        let policy = Policy::order_total_cap(cap);

        let builder = TraceBuilder::new(witness, policy);
        let trace = builder.build();

        assert!(trace.is_ok());
    }

    #[test]
    fn test_trace_builder_cap_boundary() {
        // For order total cap, amount == cap should succeed (LTE)
        let cap = 10000u64;
        let inputs = sample_inputs_cap(cap);
        let witness = ComplianceWitness::new(10000, inputs);
        let policy = Policy::order_total_cap(cap);

        let builder = TraceBuilder::new(witness, policy);
        let trace = builder.build();

        assert!(trace.is_ok());
    }

    #[test]
    fn test_trace_builder_cap_invalid() {
        let cap = 10000u64;
        let inputs = sample_inputs_cap(cap);
        let witness = ComplianceWitness::new(10001, inputs);
        let policy = Policy::order_total_cap(cap);

        let builder = TraceBuilder::new(witness, policy);
        let trace = builder.build();

        assert!(trace.is_err());
    }

    #[test]
    fn test_trace_builder_from_aml_threshold() {
        let threshold = 10000u64;
        let inputs = sample_inputs_aml(threshold);
        let witness = ComplianceWitness::new(5000, inputs);
        let policy = AmlThresholdPolicy::new(threshold);

        let builder = TraceBuilder::from_aml_threshold(witness, policy);
        let trace = builder.build();

        assert!(trace.is_ok());
    }

    #[test]
    fn test_trace_info() {
        let info = TraceInfo::new(100);
        assert_eq!(info.width, TRACE_WIDTH);
        assert_eq!(info.length, MIN_TRACE_LENGTH); // Rounds up to 128
    }

    #[test]
    fn test_bit_decomposition() {
        use super::decompose_to_bits;

        // Test decomposition of 0
        let bits = decompose_to_bits(FELT_ZERO);
        for bit in &bits {
            assert_eq!(*bit, FELT_ZERO);
        }

        // Test decomposition of 1
        let bits = decompose_to_bits(FELT_ONE);
        assert_eq!(bits[0], FELT_ONE);
        for bit in &bits[1..] {
            assert_eq!(*bit, FELT_ZERO);
        }

        // Test decomposition of 5 (binary: 101)
        let bits = decompose_to_bits(felt_from_u64(5));
        assert_eq!(bits[0], FELT_ONE);  // LSB
        assert_eq!(bits[1], FELT_ZERO);
        assert_eq!(bits[2], FELT_ONE);
        for bit in &bits[3..] {
            assert_eq!(*bit, FELT_ZERO);
        }

        // Test recomposition: sum of bits * 2^i should equal original
        let value = 12345u32;
        let bits = decompose_to_bits(felt_from_u64(value as u64));
        let mut recomposed = 0u64;
        for (i, bit) in bits.iter().enumerate() {
            if *bit == FELT_ONE {
                recomposed += 1u64 << i;
            }
        }
        assert_eq!(recomposed, value as u64);

        // Test max u32 value
        let max_u32 = u32::MAX;
        let bits = decompose_to_bits(felt_from_u64(max_u32 as u64));
        for bit in &bits {
            assert_eq!(*bit, FELT_ONE); // All bits should be 1
        }
    }

    #[test]
    fn test_trace_contains_bit_decomposition() {
        // Build a trace and verify bit columns are populated correctly
        let threshold = 10000u64;
        let amount = 5000u64;
        let inputs = sample_inputs_aml(threshold);
        let witness = ComplianceWitness::new(amount, inputs);
        let policy = Policy::aml_threshold(threshold);

        let builder = TraceBuilder::new(witness.clone(), policy);
        let trace = builder.build().unwrap();

        // Get amount limbs
        let amount_limbs = witness.amount_limbs();
        let limb0_value = amount_limbs[0].as_int() as u32;
        let limb1_value = amount_limbs[1].as_int() as u32;

        // Verify bit columns at row 0
        // Check limb 0 bits
        let mut recomposed_limb0 = 0u64;
        for i in 0..32 {
            let bit = trace.get(cols::AMOUNT_BITS_LIMB0_START + i, 0);
            if bit == FELT_ONE {
                recomposed_limb0 += 1u64 << i;
            }
        }
        assert_eq!(recomposed_limb0, limb0_value as u64, "Limb 0 bit decomposition mismatch");

        // Check limb 1 bits
        let mut recomposed_limb1 = 0u64;
        for i in 0..32 {
            let bit = trace.get(cols::AMOUNT_BITS_LIMB1_START + i, 0);
            if bit == FELT_ONE {
                recomposed_limb1 += 1u64 << i;
            }
        }
        assert_eq!(recomposed_limb1, limb1_value as u64, "Limb 1 bit decomposition mismatch");
    }

    #[test]
    fn test_witness_commitment() {
        use winter_prover::Trace;

        // Build a trace and verify witness commitment is populated
        let threshold = 10000u64;
        let amount = 5000u64;
        let inputs = sample_inputs_aml(threshold);
        let witness = ComplianceWitness::new(amount, inputs);
        let policy = Policy::aml_threshold(threshold);

        let amount_limbs = witness.amount_limbs();
        let mut rescue_init_state = [FELT_ZERO; RESCUE_STATE_WIDTH];
        rescue_init_state[..8].copy_from_slice(&amount_limbs);
        rescue_init_state[8] = felt_from_u64(8);
        let rescue_trace = rescue_permutation_trace(&rescue_init_state);
        let rescue_output_row = rescue_trace.len() - 1;
        let expected_commitment = compute_witness_commitment_from_state(
            rescue_trace.last().expect("missing Rescue state"),
        );

        let builder = TraceBuilder::new(witness, policy);
        let trace = builder.build().unwrap();

        // Verify Rescue output state columns contain the witness commitment
        for i in 0..4 {
            let trace_value = trace.get(cols::RESCUE_STATE_START + i, rescue_output_row);
            assert_eq!(trace_value, expected_commitment[i],
                "Rescue commitment column {} mismatch at output row", i);
        }

        // Verify commitment is constant across rows after the output row
        for row in rescue_output_row..trace.length() {
            for i in 0..4 {
                let trace_value = trace.get(cols::RESCUE_STATE_START + i, row);
                assert_eq!(trace_value, expected_commitment[i],
                    "Rescue commitment column {} changed at row {}", i, row);
            }
        }
    }

    #[test]
    fn test_witness_commitment_deterministic() {
        // Same amount should produce same commitment
        let limbs1 = [felt_from_u64(5000), FELT_ZERO, FELT_ZERO, FELT_ZERO,
                      FELT_ZERO, FELT_ZERO, FELT_ZERO, FELT_ZERO];
        let limbs2 = [felt_from_u64(5000), FELT_ZERO, FELT_ZERO, FELT_ZERO,
                      FELT_ZERO, FELT_ZERO, FELT_ZERO, FELT_ZERO];

        let mut rescue_init_state1 = [FELT_ZERO; RESCUE_STATE_WIDTH];
        rescue_init_state1[..8].copy_from_slice(&limbs1);
        rescue_init_state1[8] = felt_from_u64(8);
        let commitment1 = compute_witness_commitment_from_state(
            rescue_permutation_trace(&rescue_init_state1)
                .last()
                .expect("missing Rescue state"),
        );

        let mut rescue_init_state2 = [FELT_ZERO; RESCUE_STATE_WIDTH];
        rescue_init_state2[..8].copy_from_slice(&limbs2);
        rescue_init_state2[8] = felt_from_u64(8);
        let commitment2 = compute_witness_commitment_from_state(
            rescue_permutation_trace(&rescue_init_state2)
                .last()
                .expect("missing Rescue state"),
        );

        for i in 0..4 {
            assert_eq!(commitment1[i], commitment2[i],
                "Commitment not deterministic at position {}", i);
        }

        // Different amount should produce different commitment
        let limbs3 = [felt_from_u64(6000), FELT_ZERO, FELT_ZERO, FELT_ZERO,
                      FELT_ZERO, FELT_ZERO, FELT_ZERO, FELT_ZERO];
        let mut rescue_init_state3 = [FELT_ZERO; RESCUE_STATE_WIDTH];
        rescue_init_state3[..8].copy_from_slice(&limbs3);
        rescue_init_state3[8] = felt_from_u64(8);
        let commitment3 = compute_witness_commitment_from_state(
            rescue_permutation_trace(&rescue_init_state3)
                .last()
                .expect("missing Rescue state"),
        );

        let mut any_different = false;
        for i in 0..4 { // Only check first 4 elements (hash output)
            if commitment1[i] != commitment3[i] {
                any_different = true;
                break;
            }
        }
        assert!(any_different, "Different amounts should produce different commitments");
    }
}
