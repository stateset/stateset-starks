//! Batch Compliance AIR
//!
//! This module implements a **prototype** AIR for batch state transition proofs.
//! It currently enforces **consistency only**:
//! - State roots remain constant across the trace
//! - Compliance accumulator is a scaled AND over per-event flags (updated exactly once per event)
//! - Batch public inputs are bound to trace columns via boundary assertions
//!
//! It does **not** yet verify Merkle transitions or per-event proof correctness.

use ves_stark_primitives::{felt_from_u64, Felt, FELT_ONE, FELT_ZERO};
use winter_air::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};
use winter_math::FieldElement;

use crate::air::trace_layout::{batch_cols, BatchPhase, COMPLIANCE_ACC_GAMMA};
use crate::public_inputs::BatchPublicInputs;

/// Number of transition constraints in simplified batch AIR
pub const NUM_BATCH_CONSTRAINTS: usize = 54;

/// Number of boundary assertions
pub const NUM_BATCH_ASSERTIONS: usize = 44;

/// The batch compliance AIR
pub struct BatchComplianceAir {
    context: AirContext<Felt>,
    pub_inputs: BatchPublicInputs,
}

impl BatchComplianceAir {
    /// Create a new batch compliance AIR
    pub fn new(
        trace_info: TraceInfo,
        pub_inputs: BatchPublicInputs,
        options: ProofOptions,
    ) -> Self {
        // Define constraint degrees (must match evaluate_transition order).
        let mut degrees = Vec::with_capacity(NUM_BATCH_CONSTRAINTS);

        // State roots remain constant (8 constraints, degree 1).
        degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(1), 8));

        // Bound metadata / policy columns remain constant (28 constraints, degree 1).
        degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(1), 28));

        // EVENTS_DONE flag constraints.
        degrees.push(TransitionConstraintDegree::new(2)); // done binary
        degrees.push(TransitionConstraintDegree::new(2)); // done monotonic
        degrees.push(TransitionConstraintDegree::new(2)); // flip only at EVENT_ROW == 3
        degrees.push(TransitionConstraintDegree::new(2)); // flip only at EVENT_INDEX == num_events - 1
        degrees.push(TransitionConstraintDegree::new(2)); // done => EVENT_ROW == 0
        degrees.push(TransitionConstraintDegree::new(2)); // done => EVENT_INDEX == num_events

        // Event row / index progression while not done.
        degrees.push(TransitionConstraintDegree::new(3)); // EVENT_ROW increments when != 3
        degrees.push(TransitionConstraintDegree::new(5)); // EVENT_ROW wraps 3 -> 0
        degrees.push(TransitionConstraintDegree::new(3)); // EVENT_INDEX constant when EVENT_ROW != 3
        degrees.push(TransitionConstraintDegree::new(5)); // EVENT_INDEX increments on wrap

        // EVENT_ROW must be one of {0,1,2,3}.
        degrees.push(TransitionConstraintDegree::new(4));

        // Compliance accumulator constraints.
        degrees.push(TransitionConstraintDegree::new(2)); // acc constant except update row
        degrees.push(TransitionConstraintDegree::new(5)); // acc update on EVENT_ROW == 2
        degrees.push(TransitionConstraintDegree::new(2)); // flag binary

        // Phase constraints.
        degrees.push(TransitionConstraintDegree::new(2)); // phase transition
        degrees.push(TransitionConstraintDegree::new(4)); // phase validity
        degrees.push(TransitionConstraintDegree::new(2)); // not done => phase == Event
        degrees.push(TransitionConstraintDegree::new(4)); // done => phase != Event

        debug_assert_eq!(degrees.len(), NUM_BATCH_CONSTRAINTS);

        let context = AirContext::new(trace_info, degrees, NUM_BATCH_ASSERTIONS, options);

        Self {
            context,
            pub_inputs,
        }
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
        // First row assertions
        // =========================================================================

        // Previous state root must match public input
        for i in 0..4 {
            assertions.push(Assertion::single(
                batch_cols::prev_state_root(i),
                0,
                self.pub_inputs.prev_state_root[i],
            ));
        }

        // Batch metadata must match public inputs (row 0)
        for i in 0..4 {
            assertions.push(Assertion::single(
                batch_cols::batch_id(i),
                0,
                self.pub_inputs.batch_id[i],
            ));
            assertions.push(Assertion::single(
                batch_cols::TENANT_ID_START + i,
                0,
                self.pub_inputs.tenant_id[i],
            ));
            assertions.push(Assertion::single(
                batch_cols::STORE_ID_START + i,
                0,
                self.pub_inputs.store_id[i],
            ));
        }
        assertions.push(Assertion::single(
            batch_cols::SEQUENCE_START,
            0,
            self.pub_inputs.sequence_start,
        ));
        assertions.push(Assertion::single(
            batch_cols::SEQUENCE_END,
            0,
            self.pub_inputs.sequence_end,
        ));

        // Policy fields must match public inputs (row 0)
        for i in 0..8 {
            assertions.push(Assertion::single(
                batch_cols::POLICY_HASH_START + i,
                0,
                self.pub_inputs.policy_hash[i],
            ));
        }
        assertions.push(Assertion::single(
            batch_cols::POLICY_LIMIT,
            0,
            self.pub_inputs.policy_limit,
        ));

        // Compliance accumulator starts at GAMMA^{-num_events}.
        //
        // This keeps the final value as a boolean (0/1) while ensuring the accumulator is
        // non-constant even when all flags are 1.
        let num_events_u64 = self.pub_inputs.num_events.as_int();
        let gamma = Felt::new(COMPLIANCE_ACC_GAMMA);
        let gamma_inv_pow_n = gamma.exp(num_events_u64).inv();
        assertions.push(Assertion::single(
            batch_cols::COMPLIANCE_ACCUMULATOR,
            0,
            gamma_inv_pow_n,
        ));

        // Event index starts at 0
        assertions.push(Assertion::single(batch_cols::EVENT_INDEX, 0, FELT_ZERO));

        // EVENT_ROW starts at 0 (first row of first event).
        assertions.push(Assertion::single(batch_cols::EVENT_ROW, 0, FELT_ZERO));

        // Phase starts in Event (0) while events are being processed.
        assertions.push(Assertion::single(batch_cols::BATCH_PHASE, 0, FELT_ZERO));

        // EVENTS_DONE starts at 0 and must be 1 by the end of the trace.
        assertions.push(Assertion::single(batch_cols::EVENTS_DONE, 0, FELT_ZERO));
        assertions.push(Assertion::single(
            batch_cols::EVENTS_DONE,
            last_row,
            FELT_ONE,
        ));

        // EVENT_INDEX must equal num_events at the end of the trace.
        assertions.push(Assertion::single(
            batch_cols::EVENT_INDEX,
            last_row,
            self.pub_inputs.num_events,
        ));

        // First row flag
        assertions.push(Assertion::single(
            batch_cols::IS_FIRST_BATCH_ROW,
            0,
            FELT_ONE,
        ));

        // =========================================================================
        // Last row assertions
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

        // Ensure the last row is in a well-defined terminal state.
        assertions.push(Assertion::single(
            batch_cols::EVENT_ROW,
            last_row,
            FELT_ZERO,
        ));
        assertions.push(Assertion::single(
            batch_cols::BATCH_PHASE,
            last_row,
            BatchPhase::Padding.to_felt(),
        ));

        // =========================================================================
        // Metadata assertion
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
        // State roots remain constant (8)
        // =========================================================================

        for i in 0..4 {
            let col = batch_cols::prev_state_root(i);
            result[idx] = next[col] - current[col];
            idx += 1;
        }
        for i in 0..4 {
            let col = batch_cols::new_state_root(i);
            result[idx] = next[col] - current[col];
            idx += 1;
        }

        // =========================================================================
        // Public-input bound metadata remains constant (28)
        // =========================================================================

        for i in 0..4 {
            let col = batch_cols::batch_id(i);
            result[idx] = next[col] - current[col];
            idx += 1;
        }
        for i in 0..4 {
            let col = batch_cols::TENANT_ID_START + i;
            result[idx] = next[col] - current[col];
            idx += 1;
        }
        for i in 0..4 {
            let col = batch_cols::STORE_ID_START + i;
            result[idx] = next[col] - current[col];
            idx += 1;
        }
        result[idx] = next[batch_cols::SEQUENCE_START] - current[batch_cols::SEQUENCE_START];
        idx += 1;
        result[idx] = next[batch_cols::SEQUENCE_END] - current[batch_cols::SEQUENCE_END];
        idx += 1;
        result[idx] = next[batch_cols::NUM_EVENTS] - current[batch_cols::NUM_EVENTS];
        idx += 1;
        for i in 0..8 {
            let col = batch_cols::POLICY_HASH_START + i;
            result[idx] = next[col] - current[col];
            idx += 1;
        }
        result[idx] = next[batch_cols::POLICY_LIMIT] - current[batch_cols::POLICY_LIMIT];
        idx += 1;
        for i in 0..4 {
            let col = batch_cols::metadata_hash(i);
            result[idx] = next[col] - current[col];
            idx += 1;
        }

        // =========================================================================
        // EVENTS_DONE semantics (6)
        // =========================================================================

        let done = current[batch_cols::EVENTS_DONE];
        let done_next = next[batch_cols::EVENTS_DONE];

        // done is binary.
        result[idx] = done * (E::ONE - done);
        idx += 1;

        // done is monotonic: once 1, it stays 1.
        result[idx] = done * (E::ONE - done_next);
        idx += 1;

        let event_row = current[batch_cols::EVENT_ROW];
        let event_row_next = next[batch_cols::EVENT_ROW];
        let event_index = current[batch_cols::EVENT_INDEX];
        let event_index_next = next[batch_cols::EVENT_INDEX];

        let two = E::from(felt_from_u64(2));
        let three = E::from(felt_from_u64(3));

        let n = E::from(self.pub_inputs.num_events);
        let n_minus_one = n - E::ONE;

        // done can only flip on the end-of-last-event row.
        let done_delta = done_next - done;
        result[idx] = done_delta * (event_row - three);
        idx += 1;
        result[idx] = done_delta * (event_index - n_minus_one);
        idx += 1;

        // done => EVENT_ROW == 0 and EVENT_INDEX == num_events.
        result[idx] = done * event_row;
        idx += 1;
        result[idx] = done * (event_index - n);
        idx += 1;

        // =========================================================================
        // Event row/index progression while not done (4)
        // =========================================================================

        let not_done = E::ONE - done;

        // EVENT_ROW cycles 0 -> 1 -> 2 -> 3 -> 0 while not_done.
        result[idx] = not_done * (event_row - three) * (event_row_next - event_row - E::ONE);
        idx += 1;
        result[idx] =
            not_done * event_row * (event_row - E::ONE) * (event_row - two) * event_row_next;
        idx += 1;

        // EVENT_INDEX increments exactly once per event while not_done.
        result[idx] = not_done * (event_row - three) * (event_index_next - event_index);
        idx += 1;
        result[idx] = not_done
            * event_row
            * (event_row - E::ONE)
            * (event_row - two)
            * (event_index_next - event_index - E::ONE);
        idx += 1;

        // =========================================================================
        // EVENT_ROW validity (1)
        // =========================================================================

        result[idx] = event_row * (event_row - E::ONE) * (event_row - two) * (event_row - three);
        idx += 1;

        // =========================================================================
        // Compliance accumulator constraints (3)
        // =========================================================================

        // The accumulator is updated exactly once per event, on the transition into the last row
        // of the event (when EVENT_ROW == 2 on the current row).
        let acc_curr = current[batch_cols::COMPLIANCE_ACCUMULATOR];
        let acc_next = next[batch_cols::COMPLIANCE_ACCUMULATOR];
        let flag = current[batch_cols::EVENT_COMPLIANCE_FLAG];

        // When EVENT_ROW != 2, enforce acc_next == acc_curr.
        result[idx] = (event_row - two) * (acc_next - acc_curr);
        idx += 1;

        // When EVENT_ROW == 2, enforce acc_next == acc_curr * flag * gamma.
        let gamma = E::from(felt_from_u64(COMPLIANCE_ACC_GAMMA));
        result[idx] = event_row
            * (event_row - E::ONE)
            * (event_row - three)
            * (acc_next - acc_curr * flag * gamma);
        idx += 1;

        // Compliance flag is binary.
        result[idx] = flag * (E::ONE - flag);
        idx += 1;

        // =========================================================================
        // Phase constraints (4)
        // =========================================================================

        let phase_curr = current[batch_cols::BATCH_PHASE];
        let phase_next = next[batch_cols::BATCH_PHASE];

        // Phase can only stay same or increment by 1: (delta) * (delta - 1) = 0.
        let phase_delta = phase_next - phase_curr;
        result[idx] = phase_delta * (phase_delta - E::ONE);
        idx += 1;

        // Phase is in {0,1,2,3}.
        result[idx] =
            phase_curr * (phase_curr - E::ONE) * (phase_curr - two) * (phase_curr - three);
        idx += 1;

        // While not_done, phase must be Event (0).
        result[idx] = not_done * phase_curr;
        idx += 1;

        // When done, phase must not be Event (i.e. it must be in {1,2,3}).
        result[idx] = done * (phase_curr - E::ONE) * (phase_curr - two) * (phase_curr - three);
        idx += 1;

        debug_assert_eq!(idx, NUM_BATCH_CONSTRAINTS);
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air::BATCH_TRACE_WIDTH;

    #[test]
    fn test_air_creation() {
        let trace_info = TraceInfo::new(BATCH_TRACE_WIDTH, 256);
        let pub_inputs = BatchPublicInputs::default();
        let options = ves_stark_air::options::ProofOptions::default()
            .try_to_winterfell()
            .unwrap();

        let air = BatchComplianceAir::new(trace_info, pub_inputs, options);

        assert_eq!(air.context().trace_info().width(), BATCH_TRACE_WIDTH);
    }

    #[test]
    fn test_assertions_count() {
        let trace_info = TraceInfo::new(BATCH_TRACE_WIDTH, 256);
        let pub_inputs = BatchPublicInputs::default();
        let options = ves_stark_air::options::ProofOptions::default()
            .try_to_winterfell()
            .unwrap();

        let air = BatchComplianceAir::new(trace_info, pub_inputs, options);
        let assertions = air.get_assertions();

        assert_eq!(assertions.len(), NUM_BATCH_ASSERTIONS);
    }
}
