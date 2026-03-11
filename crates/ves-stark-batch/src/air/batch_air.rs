//! Batch Compliance AIR
//!
//! This module implements the batch AIR used for production-like Merkle + finalization
//! hash verification with witness binding and compliance checks.

use ves_stark_primitives::{
    felt_from_u64,
    rescue::{ROUND_CONSTANTS, STATE_WIDTH as RESCUE_STATE_WIDTH},
    Felt, FELT_ONE, FELT_ZERO,
};
use winter_air::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};
use winter_math::FieldElement;

use crate::air::constraints::{
    evaluate_compliance_binding_constraints, evaluate_leaf_binding_constraints,
    evaluate_leaf_hash_constraints, evaluate_merkle_constraints,
    NUM_COMPLIANCE_BINDING_CONSTRAINTS, NUM_LEAF_BINDING_CONSTRAINTS, NUM_LEAF_HASH_CONSTRAINTS,
    NUM_MERKLE_CONSTRAINTS, PERIODIC_COLUMN_COUNT,
};
use crate::air::trace_layout::{
    batch_cols, commitment_hash_row_count, leaf_hash_row_count, leaf_row_count, merkle_node_count,
    merkle_row_count, padded_leaf_count, BatchPhase, AMOUNT_STREAM_LANE_TAGS, COMPLIANCE_ACC_GAMMA,
    ROWS_PER_EVENT, ROWS_PER_MERKLE_NODE,
};
use crate::public_inputs::BatchPublicInputs;

/// Number of transition constraints in batch AIR.
///
/// 55 base + Merkle/finalize constraints + leaf-hash constraints + leaf-stream binding
/// + compliance binding constraints.
pub const NUM_BATCH_CONSTRAINTS: usize = 55
    + NUM_MERKLE_CONSTRAINTS
    + NUM_LEAF_HASH_CONSTRAINTS
    + NUM_LEAF_BINDING_CONSTRAINTS
    + NUM_COMPLIANCE_BINDING_CONSTRAINTS;

/// Number of boundary assertions before padded-leaf zero bindings.
pub const BASE_BATCH_ASSERTIONS: usize = 145;

/// Additional boundary assertions needed when the commitment-hash phase is present.
pub const COMMITMENT_PHASE_ASSERTIONS: usize = 13;

/// Additional boundary assertions needed when the leaf-hash phase is present.
pub const LEAF_HASH_PHASE_ASSERTIONS: usize = 13;

/// Number of boundary assertions for a batch of `num_events`.
pub fn num_batch_assertions(num_events: usize) -> usize {
    BASE_BATCH_ASSERTIONS
        + usize::from(num_events > 0) * LEAF_HASH_PHASE_ASSERTIONS
        + usize::from(num_events > 0) * COMMITMENT_PHASE_ASSERTIONS
        + padded_leaf_count(num_events).saturating_sub(num_events) * 4
}

// When the event tree has a single leaf, the explicit Merkle phase is empty and many of the
// Merkle constraints collapse to lower-degree polynomials. Winterfell validates these degrees
// exactly in debug builds, so the single-leaf case needs its own profile.
const SINGLE_LEAF_MERKLE_DEGREES: &[usize] = &[
    2, 2, 1, 2, 2, 2, 2, 1, 2, 1, 2, 1, 2, 1, 2, 2, 1, 2, 2, 2, 1, 2, 2, 2, 2, 3, 2, 3, 2, 2, 1, 2,
    2, 3, 3, 1, 3, 1, 1, 1, 1, 3, 4, 1, 4, 10, 10, 1, 10, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 4, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 1, 1, 1, 1, 9,
    9, 9, 9, 4, 4, 4, 4, 4, 4, 4, 4, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 3, 3, 3, 3, 1, 1, 1, 1, 3, 3, 3, 3, 3, 3, 3, 3,
];

const SINGLE_LEAF_LEAF_HASH_DEGREES: &[usize] = &[
    2, 2, 2, 2, 1, 2, 2, 2, 5, 3, 3, 1, 3, 4, 4, 1, 4, 1, 1, 1, 1, 6, 6, 1, 6, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 6, 6, 6, 6,
];

fn extend_merkle_degrees(degrees: &mut Vec<TransitionConstraintDegree>, num_events: usize) {
    let padded_leaves = padded_leaf_count(num_events);

    if padded_leaves == 1 {
        debug_assert_eq!(SINGLE_LEAF_MERKLE_DEGREES.len(), NUM_MERKLE_CONSTRAINTS);
        degrees.extend(
            SINGLE_LEAF_MERKLE_DEGREES
                .iter()
                .copied()
                .map(TransitionConstraintDegree::new),
        );
        return;
    }

    // 1-22) Simple structural constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(2), 22));
    // 23-24) Rescue periodic selector constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(2), 2));
    // 25) Leaf rows are always level 0.
    degrees.push(TransitionConstraintDegree::new(2));
    // 26-28) Leaf progression constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 3));
    // 29-32) Leaf-boundary transition constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 4));
    // 33) Commitment rows are always level 0.
    degrees.push(TransitionConstraintDegree::new(2));
    // 34-37) Active commitment-segment structural constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 4));
    // 38-41) Commitment output transition constraints within the commitment phase.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(4), 4));
    // 42-45) Commitment-to-Merkle inter-phase boundary constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(5), 4));
    // 46-49) Single-leaf commitment batches jump directly to finalize.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(10), 4));
    // 50-53) Active-segment Merkle structural constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 4));
    // 54-57) Same-level Merkle output transition constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(4), 4));
    // 58-61) Inter-level Merkle transition constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(5), 4));
    // 62-73) Rescue transition constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(10), 12));
    // 74-85) Hash-input binding constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(4), 8));
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 4));
    // 86-89) Final-Merkle-root binding constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 4));
    // 90-93) Single-leaf root binding constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(9), 4));
    // 94-97) Finalize-output binding constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(4), 4));
    // 98-101) Active-output binding constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(4), 4));
    // 102-105) Leaf previous-level update constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(2), 4));
    // 106-109) Leaf consumed-zero constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(2), 4));
    // 110-113) Leaf current-level-zero constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(2), 4));
    // 114-117) Commitment rows carry the leaf-level accumulator.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(2), 4));
    // 118-121) Previous-level active carry constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 4));
    // 122-125) Previous-level same-level output carry constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(4), 4));
    // 126-129) Previous-level inter-level transfer constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(5), 4));
    // 130-133) Current-level consumed init-update constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 4));
    // 134-137) Current-level consumed active carry constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(4), 4));
    // 138-141) Current-level consumed same-level output carry constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(4), 4));
    // 142-145) Current-level produced active carry constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 4));
    // 146-149) Current-level produced same-level output update constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(4), 4));
    // 150-153) Level-boundary equality constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(4), 4));
    // 154-157) Commitment accumulator active carry constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 4));
    // 158-161) Commitment accumulator output update constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(4), 4));
    // 162-165) Commitment boundary equality constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(4), 4));
    // 166-167) Amount accumulator active carry constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 2));
    // 168-169) Amount accumulator output update constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(4), 2));
    // 170-171) Amount accumulator boundary equality constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(4), 2));
    // 172-177) Commitment init upper-limb zero constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 6));
}

fn extend_leaf_hash_degrees(degrees: &mut Vec<TransitionConstraintDegree>, _num_events: usize) {
    if padded_leaf_count(_num_events) == 1 {
        debug_assert_eq!(
            SINGLE_LEAF_LEAF_HASH_DEGREES.len(),
            NUM_LEAF_HASH_CONSTRAINTS
        );
        degrees.extend(
            SINGLE_LEAF_LEAF_HASH_DEGREES
                .iter()
                .copied()
                .map(TransitionConstraintDegree::new),
        );
        return;
    }

    // 1-8) Phase/flag sanity constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(2), 8));
    // 9) Chunk index is in {0, 1, 2, 3}.
    degrees.push(TransitionConstraintDegree::new(5));
    // 10-13) Active rows stay inside the same chunk.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 4));
    // 14-17) Chunk 0 / 1 / 2 output rows advance to the next chunk of the same leaf.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(4), 4));
    // 18-21) Final chunk output rows advance to the next real leaf when present.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(7), 4));
    // 22-25) The last real leaf transitions into the commitment-hash phase.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(7), 4));
    // 26-37) Leaf -> leaf-hash boundary / chunk-input initialization constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 12));
    // 38-49) Chunk 0 output feeds chunk 1.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(6), 12));
    // 50-61) Chunk 1 output feeds chunk 2.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(6), 12));
    // 62-73) Chunk 2 output feeds chunk 3.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(6), 12));
    // 74-80) Chunk 3 only absorbs the compliance flag into lane 0.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(5), 7));
    // 81-84) Final chunk output must equal the claimed leaf hash.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(6), 4));
    // 85-88) Carry the padded-leaf accumulator from the leaf phase unchanged.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(2), 4));
    // 89-92) Active rows keep the derived leaf-hash accumulator unchanged.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 4));
    // 93-96) Chunk 0 / 1 / 2 outputs also keep the accumulator unchanged.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(4), 4));
    // 97-100) Final chunk outputs append the derived leaf hash for non-terminal leaves.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(7), 4));
    // 101-104) Final boundary matches the padded leaf stream from the leaf phase.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(7), 4));
}

fn extend_leaf_binding_degrees(degrees: &mut Vec<TransitionConstraintDegree>, num_events: usize) {
    // Event-segment leaf-hash accumulator carry constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 4));
    // Event-row leaf-hash accumulator update constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(4), 4));
    // Leaf-phase leaf-hash carry constraints.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 4));
    // Leaf-boundary leaf-hash equality constraints.
    let boundary_degree = if padded_leaf_count(num_events) == 1 {
        2
    } else {
        3
    };
    degrees.extend(std::iter::repeat_n(
        TransitionConstraintDegree::new(boundary_degree),
        4,
    ));

    // Event-segment amount-commitment stream.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 4));
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(4), 4));

    // Event-segment event-ID stream.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 4));
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(4), 4));

    // Event-segment policy-hash stream.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 8));
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(4), 8));

    // Event-segment canonical public-input hash stream.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 8));
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(4), 8));

    // Event-segment amount-limb stream.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 2));
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(4), 2));

    // Event-segment compliance-flag stream.
    degrees.push(TransitionConstraintDegree::new(3));
    degrees.push(TransitionConstraintDegree::new(4));

    // Leaf rows carry the terminal event-side streams forward.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 4));
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 4));
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 8));
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 8));
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(3), 2));
    degrees.push(TransitionConstraintDegree::new(3));

    // Leaf-side stream updates.
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(2), 4));
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(2), 4));
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(2), 8));
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(2), 8));
    degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(2), 2));
    degrees.push(TransitionConstraintDegree::new(2));

    // Boundary equality between event-side and leaf-side exact streams.
    degrees.extend(std::iter::repeat_n(
        TransitionConstraintDegree::new(boundary_degree),
        4,
    ));
    degrees.extend(std::iter::repeat_n(
        TransitionConstraintDegree::new(boundary_degree),
        4,
    ));
    degrees.extend(std::iter::repeat_n(
        TransitionConstraintDegree::new(boundary_degree),
        8,
    ));
    degrees.extend(std::iter::repeat_n(
        TransitionConstraintDegree::new(boundary_degree),
        8,
    ));
    degrees.extend(std::iter::repeat_n(
        TransitionConstraintDegree::new(boundary_degree),
        2,
    ));
    degrees.push(TransitionConstraintDegree::new(boundary_degree));
}

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

        // Bound metadata / policy columns remain constant (29 constraints, degree 1).
        degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(1), 29));

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
        degrees.push(TransitionConstraintDegree::new(4)); // phase transition
        degrees.push(TransitionConstraintDegree::new(7)); // phase validity
        degrees.push(TransitionConstraintDegree::new(2)); // not done => phase == Event
        degrees.push(TransitionConstraintDegree::new(7)); // done => phase != Event

        let num_events = pub_inputs.num_events.as_int() as usize;
        extend_merkle_degrees(&mut degrees, num_events);
        extend_leaf_hash_degrees(&mut degrees, num_events);
        extend_leaf_binding_degrees(&mut degrees, num_events);

        // Compliance binding constraints (§2).
        // 64 amount bit binary constraints on row 0: degree 6
        degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(6), 64));
        // 2 amount recomposition constraints on row 0: degree 5
        degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(5), 2));
        // 12 upper-limb zero constraints on row 0: degree 5
        degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(5), 12));
        // 64 diff bit binary constraints on row 1: degree 6
        degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(6), 64));
        // 2 diff recomposition constraints on row 1: degree 5
        degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(5), 2));
        // 2 borrow binary constraints on row 1: degree 6
        degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(6), 2));
        // 2 subtraction constraints on row 1: degree 5
        degrees.extend(std::iter::repeat_n(TransitionConstraintDegree::new(5), 2));
        // 1 flag binding constraint on row 2: degree 5
        degrees.push(TransitionConstraintDegree::new(5));

        debug_assert_eq!(degrees.len(), NUM_BATCH_CONSTRAINTS);

        let context = AirContext::new(
            trace_info,
            degrees,
            num_batch_assertions(pub_inputs.num_events.as_int() as usize),
            options,
        );

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
        let num_events = self.pub_inputs.num_events.as_int() as usize;
        let mut assertions = Vec::with_capacity(num_batch_assertions(num_events));
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
        assertions.push(Assertion::single(
            batch_cols::TIMESTAMP,
            0,
            self.pub_inputs.timestamp,
        ));

        let expected_metadata_hash = self.pub_inputs.metadata_hash();
        for (i, lane) in expected_metadata_hash.iter().enumerate() {
            assertions.push(Assertion::single(batch_cols::metadata_hash(i), 0, *lane));
        }

        // Policy fields must match public inputs (row 0)
        let expected_policy_hash = self.pub_inputs.policy_hash_or_zero();
        for (i, lane) in expected_policy_hash.iter().enumerate() {
            assertions.push(Assertion::single(
                batch_cols::POLICY_HASH_START + i,
                0,
                *lane,
            ));
        }
        assertions.push(Assertion::single(
            batch_cols::POLICY_LIMIT,
            0,
            self.pub_inputs.policy_limit,
        ));

        // Compliance accumulator starts at GAMMA^{-num_events}.
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
        for i in 0..4 {
            assertions.push(Assertion::single(batch_cols::merkle_right(i), 0, FELT_ZERO));
            assertions.push(Assertion::single(
                batch_cols::event_commitment_acc(i),
                0,
                FELT_ZERO,
            ));
            assertions.push(Assertion::single(batch_cols::event_id_acc(i), 0, FELT_ZERO));
        }
        for i in 0..8 {
            assertions.push(Assertion::single(
                batch_cols::event_policy_acc(i),
                0,
                FELT_ZERO,
            ));
            assertions.push(Assertion::single(
                batch_cols::event_public_inputs_acc(i),
                0,
                FELT_ZERO,
            ));
        }
        for i in 0..2 {
            assertions.push(Assertion::single(
                batch_cols::event_amount_acc(i),
                0,
                FELT_ZERO,
            ));
        }
        assertions.push(Assertion::single(batch_cols::EVENT_FLAG_ACC, 0, FELT_ZERO));

        // =========================================================================
        // Leaf phase anchors
        // =========================================================================

        let event_rows = num_events * ROWS_PER_EVENT;
        let leaf_rows = leaf_row_count(num_events);
        let leaf_hash_rows = leaf_hash_row_count(num_events);
        let commitment_rows = commitment_hash_row_count(num_events);
        let padded_leaves = padded_leaf_count(num_events);
        let padding_leaf_rows = padded_leaves.saturating_sub(num_events);
        let padding_start = event_rows + num_events;
        let leaf_hash_start = event_rows + leaf_rows;
        let commitment_start = leaf_hash_start + leaf_hash_rows;
        let finalize_start = commitment_start + commitment_rows + merkle_row_count(num_events);
        let has_padding_rows =
            finalize_start + crate::air::trace_layout::FINALIZE_ROWS < self.trace_length();

        for i in 0..8 {
            assertions.push(Assertion::single(
                batch_cols::event_public_inputs_acc(i),
                event_rows,
                self.pub_inputs.public_inputs_accumulator[i],
            ));
        }

        assertions.push(Assertion::single(
            batch_cols::BATCH_PHASE,
            event_rows,
            BatchPhase::Leaf.to_felt(),
        ));
        assertions.push(Assertion::single(
            batch_cols::IS_LEAF_ROW,
            event_rows,
            FELT_ONE,
        ));
        assertions.push(Assertion::single(
            batch_cols::MERKLE_LEVEL,
            event_rows,
            FELT_ZERO,
        ));
        assertions.push(Assertion::single(
            batch_cols::MERKLE_NODE_INDEX,
            event_rows,
            FELT_ZERO,
        ));
        assertions.push(Assertion::single(
            batch_cols::MERKLE_LEVEL_SIZE,
            event_rows,
            felt_from_u64(padded_leaves as u64),
        ));
        for i in 0..4 {
            assertions.push(Assertion::single(
                batch_cols::leaf_commitment_acc(i),
                event_rows,
                FELT_ZERO,
            ));
            assertions.push(Assertion::single(
                batch_cols::leaf_id_acc(i),
                event_rows,
                FELT_ZERO,
            ));
            assertions.push(Assertion::single(
                batch_cols::merkle_prev_level_acc(i),
                event_rows,
                FELT_ZERO,
            ));
            assertions.push(Assertion::single(
                batch_cols::merkle_consumed_level_acc(i),
                event_rows,
                FELT_ZERO,
            ));
            assertions.push(Assertion::single(
                batch_cols::merkle_curr_level_acc(i),
                event_rows,
                FELT_ZERO,
            ));
        }
        for i in 0..8 {
            assertions.push(Assertion::single(
                batch_cols::leaf_policy_acc(i),
                event_rows,
                FELT_ZERO,
            ));
            assertions.push(Assertion::single(
                batch_cols::leaf_public_inputs_acc(i),
                event_rows,
                FELT_ZERO,
            ));
        }
        for i in 0..2 {
            assertions.push(Assertion::single(
                batch_cols::leaf_amount_acc(i),
                event_rows,
                FELT_ZERO,
            ));
        }
        assertions.push(Assertion::single(
            batch_cols::LEAF_FLAG_ACC,
            event_rows,
            FELT_ZERO,
        ));

        // =========================================================================
        // Leaf-hash phase anchors
        // =========================================================================

        if leaf_hash_rows > 0 {
            assertions.push(Assertion::single(
                batch_cols::BATCH_PHASE,
                leaf_hash_start,
                BatchPhase::LeafHash.to_felt(),
            ));
            assertions.push(Assertion::single(
                batch_cols::IS_LEAF_HASH_ROW,
                leaf_hash_start,
                FELT_ONE,
            ));
            assertions.push(Assertion::single(
                batch_cols::MERKLE_LEVEL,
                leaf_hash_start,
                FELT_ZERO,
            ));
            assertions.push(Assertion::single(
                batch_cols::MERKLE_NODE_INDEX,
                leaf_hash_start,
                FELT_ZERO,
            ));
            assertions.push(Assertion::single(
                batch_cols::MERKLE_LEVEL_SIZE,
                leaf_hash_start,
                felt_from_u64(padded_leaves as u64),
            ));
            for i in 0..4 {
                assertions.push(Assertion::single(
                    batch_cols::merkle_consumed_level_acc(i),
                    leaf_hash_start,
                    FELT_ZERO,
                ));
                assertions.push(Assertion::single(
                    batch_cols::merkle_curr_level_acc(i),
                    leaf_hash_start,
                    FELT_ZERO,
                ));
            }
        }

        // =========================================================================
        // Commitment-hash phase anchors
        // =========================================================================

        if commitment_rows > 0 {
            assertions.push(Assertion::single(
                batch_cols::BATCH_PHASE,
                commitment_start,
                BatchPhase::CommitmentHash.to_felt(),
            ));
            assertions.push(Assertion::single(
                batch_cols::IS_COMMITMENT_HASH_ROW,
                commitment_start,
                FELT_ONE,
            ));
            assertions.push(Assertion::single(
                batch_cols::MERKLE_LEVEL,
                commitment_start,
                FELT_ZERO,
            ));
            assertions.push(Assertion::single(
                batch_cols::MERKLE_NODE_INDEX,
                commitment_start,
                FELT_ZERO,
            ));
            assertions.push(Assertion::single(
                batch_cols::MERKLE_LEVEL_SIZE,
                commitment_start,
                felt_from_u64(padded_leaves as u64),
            ));
            for i in 0..4 {
                assertions.push(Assertion::single(
                    batch_cols::merkle_curr_level_acc(i),
                    commitment_start,
                    FELT_ZERO,
                ));
                assertions.push(Assertion::single(
                    batch_cols::merkle_consumed_level_acc(i),
                    commitment_start,
                    FELT_ZERO,
                ));
            }
        }

        // Padded leaves must be actual zero leaves, matching `EventMerkleTree::from_leaf_hashes`.
        for row in padding_start..padding_start + padding_leaf_rows {
            for i in 0..4 {
                assertions.push(Assertion::single(
                    batch_cols::merkle_output(i),
                    row,
                    FELT_ZERO,
                ));
            }
        }

        // =========================================================================
        // Finalize phase anchors
        // =========================================================================

        assertions.push(Assertion::single(
            batch_cols::BATCH_PHASE,
            finalize_start,
            BatchPhase::Finalize.to_felt(),
        ));
        assertions.push(Assertion::single(
            batch_cols::IS_FINALIZE_HASH,
            finalize_start,
            FELT_ONE,
        ));
        assertions.push(Assertion::single(
            batch_cols::MERKLE_LEVEL,
            finalize_start,
            FELT_ZERO,
        ));
        assertions.push(Assertion::single(
            batch_cols::MERKLE_NODE_INDEX,
            finalize_start,
            FELT_ZERO,
        ));
        assertions.push(Assertion::single(
            batch_cols::MERKLE_LEVEL_SIZE,
            finalize_start,
            FELT_ZERO,
        ));
        for i in 0..4 {
            assertions.push(Assertion::single(
                batch_cols::merkle_consumed_level_acc(i),
                finalize_start,
                FELT_ZERO,
            ));
            assertions.push(Assertion::single(
                batch_cols::merkle_curr_level_acc(i),
                finalize_start,
                FELT_ZERO,
            ));
        }

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
            if has_padding_rows {
                BatchPhase::Padding.to_felt()
            } else {
                BatchPhase::Finalize.to_felt()
            },
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

        debug_assert_eq!(assertions.len(), num_batch_assertions(num_events));

        assertions
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
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
        // Public-input bound metadata remains constant (29)
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
        result[idx] = next[batch_cols::TIMESTAMP] - current[batch_cols::TIMESTAMP];
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
        let four = E::from(felt_from_u64(4));

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

        // Phase can stay the same or increment by 1. A single-event batch may also jump
        // directly from CommitmentHash to Finalize because there is no internal Merkle phase.
        let phase_delta = phase_next - phase_curr;
        let is_commit_to_finalize =
            current[batch_cols::IS_COMMITMENT_HASH_ROW] * next[batch_cols::IS_FINALIZE_HASH];
        result[idx] =
            phase_delta * (phase_delta - E::ONE) * (phase_delta - two * is_commit_to_finalize);
        idx += 1;

        // Phase is in {0,1,2,3,4,5,6}.
        result[idx] = phase_curr
            * (phase_curr - E::ONE)
            * (phase_curr - two)
            * (phase_curr - three)
            * (phase_curr - four);
        let five = E::from(felt_from_u64(5));
        let six = E::from(felt_from_u64(6));
        result[idx] *= (phase_curr - five) * (phase_curr - six);
        idx += 1;

        // While not_done, phase must be Event (0).
        result[idx] = not_done * phase_curr;
        idx += 1;

        // When done, phase must be in {1,2,3,4,5,6}.
        result[idx] = done
            * (phase_curr - E::ONE)
            * (phase_curr - two)
            * (phase_curr - three)
            * (phase_curr - four)
            * (phase_curr - five)
            * (phase_curr - six);
        idx += 1;

        // =========================================================================
        // Merkle structural constraints (NUM_MERKLE_CONSTRAINTS)
        // =========================================================================

        let used =
            evaluate_merkle_constraints::<E>(current, next, periodic_values, &mut result[idx..]);
        idx += used;

        // =========================================================================
        let num_events = self.pub_inputs.num_events.as_int() as usize;
        let padding_rows = padded_leaf_count(num_events) - num_events;
        let leaf_gamma = Felt::new(crate::air::trace_layout::MERKLE_LINK_GAMMA);
        let padding_gamma = E::from(leaf_gamma.exp(padding_rows as u64));

        // =========================================================================
        // Leaf-hash phase constraints (NUM_LEAF_HASH_CONSTRAINTS)
        // =========================================================================

        let used = evaluate_leaf_hash_constraints::<E>(
            current,
            next,
            periodic_values,
            padding_gamma,
            &mut result[idx..],
        );
        idx += used;

        // =========================================================================
        // Event-to-leaf stream binding constraints (NUM_LEAF_BINDING_CONSTRAINTS)
        // =========================================================================

        let amount_padding_offsets = AMOUNT_STREAM_LANE_TAGS.map(|tag| {
            let mut offset = FELT_ZERO;
            for _ in 0..padding_rows {
                offset = offset * leaf_gamma + felt_from_u64(tag);
            }
            E::from(offset)
        });
        let policy_padding_offsets = self.pub_inputs.policy_hash_or_zero().map(|lane| {
            let mut offset = FELT_ZERO;
            for _ in 0..padding_rows {
                offset = offset * leaf_gamma + lane;
            }
            E::from(offset)
        });
        let used = evaluate_leaf_binding_constraints::<E>(
            current,
            next,
            padding_gamma,
            amount_padding_offsets,
            policy_padding_offsets,
            &mut result[idx..],
        );
        idx += used;

        // =========================================================================
        // Compliance binding constraints (NUM_COMPLIANCE_BINDING_CONSTRAINTS)
        // =========================================================================

        let used = evaluate_compliance_binding_constraints::<E>(current, &mut result[idx..]);
        idx += used;

        debug_assert_eq!(idx, NUM_BATCH_CONSTRAINTS);
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let trace_len = self.trace_length();
        let mut columns = Vec::with_capacity(PERIODIC_COLUMN_COUNT);

        let num_events = self.pub_inputs.num_events.as_int() as usize;
        let mut rescue_active = vec![FELT_ZERO; trace_len];
        let mut rescue_init = vec![FELT_ZERO; trace_len];
        let mut rescue_is_forward = vec![FELT_ZERO; trace_len];

        let mut round_columns: Vec<Vec<Felt>> = (0..RESCUE_STATE_WIDTH)
            .map(|_| vec![FELT_ZERO; trace_len])
            .collect();

        let mut row = num_events * ROWS_PER_EVENT + leaf_row_count(num_events);

        // Build four hash segments per real leaf preimage, one per real-event amount
        // commitment, one per internal Merkle node, and one finalization segment.
        let hash_segments = (4 * num_events) + num_events + merkle_node_count(num_events) + 1;
        for _ in 0..hash_segments {
            for step in 0..ROWS_PER_MERKLE_NODE {
                if row >= trace_len {
                    break;
                }

                if step < (ROWS_PER_MERKLE_NODE - 1) {
                    rescue_active[row] = FELT_ONE;
                    rescue_is_forward[row] = if step % 2 == 0 { FELT_ONE } else { FELT_ZERO };
                    for col in 0..RESCUE_STATE_WIDTH {
                        round_columns[col][row] = felt_from_u64(ROUND_CONSTANTS[step][col]);
                    }
                }

                if step == 0 {
                    rescue_init[row] = FELT_ONE;
                }

                row += 1;
            }
        }

        columns.push(rescue_active);
        columns.push(rescue_init);
        columns.push(rescue_is_forward);
        for col in round_columns {
            columns.push(col);
        }

        debug_assert_eq!(columns.len(), PERIODIC_COLUMN_COUNT);
        columns
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air::BATCH_TRACE_WIDTH;
    use crate::public_inputs::BatchPolicyKind;

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

        assert_eq!(assertions.len(), num_batch_assertions(0));
    }

    #[test]
    fn test_assertions_with_invalid_policy_kind_do_not_panic() {
        let trace_info = TraceInfo::new(BATCH_TRACE_WIDTH, 256);
        let mut pub_inputs = BatchPublicInputs::new(
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
        pub_inputs.policy_kind = felt_from_u64(99);
        let options = ves_stark_air::options::ProofOptions::default()
            .try_to_winterfell()
            .unwrap();

        let air = BatchComplianceAir::new(trace_info, pub_inputs, options);
        let assertions = air.get_assertions();

        assert_eq!(assertions.len(), num_batch_assertions(1));
    }
}
