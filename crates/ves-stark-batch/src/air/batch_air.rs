//! Batch Compliance AIR
//!
//! This module implements a **prototype** AIR for batch state transition proofs.
//! It currently enforces **consistency only**:
//! - State roots remain constant across the trace
//! - Compliance accumulator is an AND over per-event flags
//! - Metadata fields remain constant
//!
//! It does **not** yet verify Merkle transitions or per-event proof correctness.

use ves_stark_primitives::{Felt, felt_from_u64, FELT_ZERO, FELT_ONE};
use winter_air::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};
use winter_math::FieldElement;

use crate::air::trace_layout::batch_cols;
use crate::public_inputs::BatchPublicInputs;

/// Number of transition constraints in simplified batch AIR
pub const NUM_BATCH_CONSTRAINTS: usize = 32;

/// Number of boundary assertions
pub const NUM_BATCH_ASSERTIONS: usize = 14;

/// The batch compliance AIR
pub struct BatchComplianceAir {
    context: AirContext<Felt>,
    pub_inputs: BatchPublicInputs,
}

impl BatchComplianceAir {
    /// Create a new batch compliance AIR
    pub fn new(trace_info: TraceInfo, pub_inputs: BatchPublicInputs, options: ProofOptions) -> Self {
        // Define constraint degrees
        let mut degrees = Vec::with_capacity(NUM_BATCH_CONSTRAINTS);

        // State root consistency (8 constraints, degree 1)
        for _ in 0..8 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Metadata consistency (8 constraints, degree 1)
        for _ in 0..8 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Compliance accumulator (2 constraints, degree 2)
        degrees.push(TransitionConstraintDegree::new(2));
        degrees.push(TransitionConstraintDegree::new(2));

        // Phase constraints (2 constraints)
        degrees.push(TransitionConstraintDegree::new(2)); // phase transition
        degrees.push(TransitionConstraintDegree::new(4)); // phase validity (degree 4)

        // Padding constraints (12 constraints, degree 1)
        while degrees.len() < NUM_BATCH_CONSTRAINTS {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        let context = AirContext::new(trace_info, degrees, NUM_BATCH_ASSERTIONS, options);

        Self { context, pub_inputs }
    }

    /// Get the public inputs
    pub fn public_inputs(&self) -> &BatchPublicInputs {
        &self.pub_inputs
    }
}

impl Air for BatchComplianceAir {
    type BaseField = Felt;
    type PublicInputs = BatchPublicInputs;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        BatchComplianceAir::new(trace_info, pub_inputs, options)
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::with_capacity(NUM_BATCH_ASSERTIONS);
        let last_row = self.trace_length() - 1;

        // =========================================================================
        // First row assertions (7 assertions)
        // =========================================================================

        // Previous state root must match public input
        for i in 0..4 {
            assertions.push(Assertion::single(
                batch_cols::prev_state_root(i),
                0,
                self.pub_inputs.prev_state_root[i],
            ));
        }

        // Compliance accumulator starts at 1
        assertions.push(Assertion::single(
            batch_cols::COMPLIANCE_ACCUMULATOR,
            0,
            FELT_ONE,
        ));

        // Event index starts at 0
        assertions.push(Assertion::single(
            batch_cols::EVENT_INDEX,
            0,
            FELT_ZERO,
        ));

        // First row flag
        assertions.push(Assertion::single(
            batch_cols::IS_FIRST_BATCH_ROW,
            0,
            FELT_ONE,
        ));

        // =========================================================================
        // Last row assertions (6 assertions)
        // =========================================================================

        // New state root must match public input
        for i in 0..4 {
            assertions.push(Assertion::single(
                batch_cols::new_state_root(i),
                last_row,
                self.pub_inputs.new_state_root[i],
            ));
        }

        // Compliance accumulator must match expected value
        assertions.push(Assertion::single(
            batch_cols::COMPLIANCE_ACCUMULATOR,
            last_row,
            self.pub_inputs.all_compliant,
        ));

        // Last row flag
        assertions.push(Assertion::single(
            batch_cols::IS_LAST_BATCH_ROW,
            last_row,
            FELT_ONE,
        ));

        // =========================================================================
        // Metadata assertion (1 assertion)
        // =========================================================================

        // Number of events at row 0
        assertions.push(Assertion::single(
            batch_cols::NUM_EVENTS,
            0,
            self.pub_inputs.num_events,
        ));

        assertions
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        let mut idx = 0;

        // =========================================================================
        // State root consistency constraints (8)
        // State roots must remain constant throughout the trace
        // =========================================================================

        // Previous state root stays constant
        for i in 0..4 {
            let col = batch_cols::prev_state_root(i);
            result[idx] = next[col] - current[col];
            idx += 1;
        }

        // New state root stays constant
        for i in 0..4 {
            let col = batch_cols::new_state_root(i);
            result[idx] = next[col] - current[col];
            idx += 1;
        }

        // =========================================================================
        // Metadata consistency constraints (8)
        // =========================================================================

        // Batch ID stays constant
        for i in 0..4 {
            let col = batch_cols::batch_id(i);
            result[idx] = next[col] - current[col];
            idx += 1;
        }

        // Metadata hash stays constant
        for i in 0..4 {
            let col = batch_cols::metadata_hash(i);
            result[idx] = next[col] - current[col];
            idx += 1;
        }

        // =========================================================================
        // Compliance accumulator constraints (2)
        // =========================================================================

        // Accumulator update: next = current * compliance_flag
        let acc_curr = current[batch_cols::COMPLIANCE_ACCUMULATOR];
        let acc_next = next[batch_cols::COMPLIANCE_ACCUMULATOR];
        let flag = current[batch_cols::EVENT_COMPLIANCE_FLAG];

        // Enforce AND accumulation
        result[idx] = acc_next - acc_curr * flag;
        idx += 1;

        // Compliance flag is binary
        result[idx] = flag * (E::ONE - flag);
        idx += 1;

        // =========================================================================
        // Phase constraints (2)
        // =========================================================================

        let phase_curr = current[batch_cols::BATCH_PHASE];
        let phase_next = next[batch_cols::BATCH_PHASE];

        // Phase can only stay same or increment by 1
        // (next - curr) * (next - curr - 1) = 0
        result[idx] = (phase_next - phase_curr) * (phase_next - phase_curr - E::ONE);
        idx += 1;

        // Phase is in valid range (0, 1, 2, or 3)
        // phase * (phase - 1) * (phase - 2) * (phase - 3) = 0
        // Simplified: we just check it doesn't exceed 3
        let three = E::from(felt_from_u64(3));
        result[idx] = phase_curr * (phase_curr - E::ONE) * (phase_curr - E::from(felt_from_u64(2))) * (phase_curr - three);
        idx += 1;

        // =========================================================================
        // Padding constraints (fill remaining with zeros)
        // =========================================================================

        while idx < NUM_BATCH_CONSTRAINTS {
            result[idx] = E::ZERO;
            idx += 1;
        }
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_air_creation() {
        let trace_info = TraceInfo::new(BATCH_TRACE_WIDTH, 256);
        let pub_inputs = BatchPublicInputs::default();
        let options = ves_stark_air::options::ProofOptions::default().to_winterfell();

        let air = BatchComplianceAir::new(trace_info, pub_inputs, options);

        assert_eq!(air.context().trace_info().width(), BATCH_TRACE_WIDTH);
    }

    #[test]
    fn test_assertions_count() {
        let trace_info = TraceInfo::new(BATCH_TRACE_WIDTH, 256);
        let pub_inputs = BatchPublicInputs::default();
        let options = ves_stark_air::options::ProofOptions::default().to_winterfell();

        let air = BatchComplianceAir::new(trace_info, pub_inputs, options);
        let assertions = air.get_assertions();

        assert_eq!(assertions.len(), NUM_BATCH_ASSERTIONS);
    }
}
