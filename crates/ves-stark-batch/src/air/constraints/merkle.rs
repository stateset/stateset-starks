//! Merkle tree and state-root finalization constraints.
//!
//! This module constrains hash rows in the Merkle and finalize phases:
//! - phase/phase-row/phase-index structural checks
//! - Rescue-Prime transition checks on each hash step row
//! - hash input/output binding for all hash rows

use crate::air::trace_layout::batch_cols;
use ves_stark_primitives::{
    felt_from_u64,
    rescue::{MDS, MDS_INV, STATE_WIDTH as RESCUE_STATE_WIDTH},
    Felt,
};
use winter_math::FieldElement;

/// Number of constraints produced by `evaluate_merkle_constraints`.
///
/// Layout:
/// - 11 structural constraints (phase, binary, row-zero, after-events, activity, init)
/// - 12 Rescue transition constraints (12 state words)
/// - 12 hash-input binding constraints (Merkle/finalize-specific)
/// - 12 output/state-binding constraints (final Merkle root + finalize output + active output)
///
/// Total: 47
pub const NUM_MERKLE_CONSTRAINTS: usize = 47;

/// Index in periodic columns for Rescue activity selector.
pub const PERIODIC_RESCUE_ACTIVE_IDX: usize = 0;

/// Index in periodic columns for Rescue init selector.
pub const PERIODIC_RESCUE_INIT_IDX: usize = 1;

/// Index in periodic columns for Rescue direction selector.
pub const PERIODIC_RESCUE_IS_FORWARD_IDX: usize = 2;

/// Index in periodic columns where Rescue round constants start.
pub const PERIODIC_RESCUE_CONST_START_IDX: usize = 3;

/// Total number of Rescue periodic columns.
pub const PERIODIC_COLUMN_COUNT: usize = PERIODIC_RESCUE_CONST_START_IDX + RESCUE_STATE_WIDTH;

#[inline]
fn pow7<E: FieldElement<BaseField = Felt>>(x: E) -> E {
    let x2 = x * x;
    let x4 = x2 * x2;
    let x6 = x4 * x2;
    x6 * x
}


fn apply_mds<E: FieldElement<BaseField = Felt>>(
    state: &[E; RESCUE_STATE_WIDTH],
    matrix: &[[u64; RESCUE_STATE_WIDTH]; RESCUE_STATE_WIDTH],
) -> [E; RESCUE_STATE_WIDTH] {
    let mut result = [E::ZERO; RESCUE_STATE_WIDTH];
    for (i, row) in matrix.iter().enumerate() {
        let mut sum = E::ZERO;
        for (&coeff, &s) in row.iter().zip(state.iter()) {
            sum += E::from(felt_from_u64(coeff)) * s;
        }
        result[i] = sum;
    }
    result
}

#[inline]
fn felt_to_ext<E: FieldElement<BaseField = Felt>>(val: u64) -> E {
    E::from(felt_from_u64(val))
}

/// Evaluate Merkle and finalization hash constraints
pub fn evaluate_merkle_constraints<E: FieldElement<BaseField = Felt>>(
    current: &[E],
    next: &[E],
    periodic_values: &[E],
    result: &mut [E],
) -> usize {
    let mut idx = 0;

    let is_merkle = current[batch_cols::IS_MERKLE_ROW];
    let is_finalize = current[batch_cols::IS_FINALIZE_HASH];
    let is_hash_row = is_merkle + is_finalize;

    let phase = current[batch_cols::BATCH_PHASE];
    let event_row = current[batch_cols::EVENT_ROW];
    let event_index = current[batch_cols::EVENT_INDEX];
    let num_events = current[batch_cols::NUM_EVENTS];

    let rescue_active = periodic_values[PERIODIC_RESCUE_ACTIVE_IDX];
    let rescue_init = periodic_values[PERIODIC_RESCUE_INIT_IDX];
    let rescue_is_forward = periodic_values[PERIODIC_RESCUE_IS_FORWARD_IDX];

    let mut round_const = [E::ZERO; RESCUE_STATE_WIDTH];
    for i in 0..RESCUE_STATE_WIDTH {
        round_const[i] = periodic_values[PERIODIC_RESCUE_CONST_START_IDX + i];
    }

    let is_hash_row_active = is_hash_row * rescue_active;
    let is_output_row = is_hash_row * (E::ONE - rescue_active);
    let is_final_merkle_row = is_merkle * (E::ONE - next[batch_cols::IS_MERKLE_ROW]);

    // 1) Merkle rows are in phase 1.
    result[idx] = is_merkle * (phase - E::ONE);
    idx += 1;

    // 2) Finalize rows are in phase 2.
    let two = felt_to_ext::<E>(2);
    result[idx] = is_finalize * (phase - two);
    idx += 1;

    // 3) Hash rows are either Merkle or finalize, not both.
    result[idx] = is_merkle * is_finalize;
    idx += 1;

    // 4) Merkle rows are binary.
    result[idx] = is_merkle * (E::ONE - is_merkle);
    idx += 1;

    // 5) Finalize rows are binary.
    result[idx] = is_finalize * (E::ONE - is_finalize);
    idx += 1;

    // 6) Hash rows are on row zero.
    result[idx] = is_merkle * event_row;
    idx += 1;

    // 7) Finalize rows are on row zero.
    result[idx] = is_finalize * event_row;
    idx += 1;

    // 8) Merkle/finalize rows happen at or after index == num_events.
    result[idx] = is_merkle * (event_index - num_events);
    idx += 1;
    result[idx] = is_finalize * (event_index - num_events);
    idx += 1;

    // 9) Active rows belong to hash rows.
    result[idx] = rescue_active * (is_hash_row - E::ONE);
    idx += 1;

    // 10) Init rows belong to hash rows.
    result[idx] = rescue_init * (is_hash_row - E::ONE);
    idx += 1;

    let mut curr_state = [E::ZERO; RESCUE_STATE_WIDTH];
    let mut next_state = [E::ZERO; RESCUE_STATE_WIDTH];
    let rescue_state_start = batch_cols::MERKLE_RESCUE_STATE_START;
    let rescue_state_end = rescue_state_start + RESCUE_STATE_WIDTH;
    curr_state.copy_from_slice(&current[rescue_state_start..rescue_state_end]);
    next_state.copy_from_slice(&next[rescue_state_start..rescue_state_end]);

    // 11-22) Rescue permutation transitions on active hash rows.
    //
    // Forward half-round:  next = MDS * sbox(curr) + constants
    //   Constraint: next - MDS * sbox(curr) - constants = 0  (degree 7 in trace)
    //
    // Backward half-round: next = sbox_inv(MDS_inv * curr) + constants
    //   Rewritten as: sbox(next - constants) = MDS_inv * curr  (degree 7 in trace)
    //   Using sbox instead of sbox_inv avoids a degree-alpha_inv (~10^19) constraint.
    let mut sbox_state = [E::ZERO; RESCUE_STATE_WIDTH];
    for i in 0..RESCUE_STATE_WIDTH {
        sbox_state[i] = pow7(curr_state[i]);
    }

    let forward_state = apply_mds(&sbox_state, &MDS);
    let backward_state = apply_mds(&curr_state, &MDS_INV);

    for i in 0..RESCUE_STATE_WIDTH {
        let forward_constraint = next_state[i] - (forward_state[i] + round_const[i]);
        let backward_constraint = pow7(next_state[i] - round_const[i]) - backward_state[i];
        let transition = rescue_is_forward * forward_constraint
            + (E::ONE - rescue_is_forward) * backward_constraint;
        result[idx] = is_hash_row_active * transition;
        idx += 1;
    }

    // 23-34) Hash initialization.
    for i in 0..RESCUE_STATE_WIDTH {
        let merkle_input = if i < 4 {
            current[batch_cols::merkle_left(i)]
        } else if i < 8 {
            current[batch_cols::merkle_right(i - 4)]
        } else {
            E::ZERO
        };
        let finalize_input = if i < 4 {
            current[batch_cols::event_tree_root(i)]
        } else if i < 8 {
            current[batch_cols::metadata_hash(i - 4)]
        } else {
            E::ZERO
        };
        let expected = is_merkle * merkle_input + is_finalize * finalize_input;

        result[idx] = rescue_init * (curr_state[i] - expected);
        idx += 1;
    }

    // 35-38) Final Merkle row must match event-tree root.
    for i in 0..4 {
        result[idx] = is_final_merkle_row * (current[batch_cols::merkle_output(i)] - current[batch_cols::event_tree_root(i)]);
        idx += 1;
    }

    // 39-42) Output row for finalize hash equals new state root.
    result[idx] = is_output_row
        * is_finalize
        * (current[batch_cols::merkle_rescue_state(0)]
            - current[batch_cols::new_state_root(0)]);
    idx += 1;
    result[idx] = is_output_row
        * is_finalize
        * (current[batch_cols::merkle_rescue_state(1)]
            - current[batch_cols::new_state_root(1)]);
    idx += 1;
    result[idx] = is_output_row
        * is_finalize
        * (current[batch_cols::merkle_rescue_state(2)]
            - current[batch_cols::new_state_root(2)]);
    idx += 1;
    result[idx] = is_output_row
        * is_finalize
        * (current[batch_cols::merkle_rescue_state(3)]
            - current[batch_cols::new_state_root(3)]);
    idx += 1;

    // 43-46) Active output rows bind state to event-tree node output / final root.
    result[idx] = is_output_row * is_merkle * (current[batch_cols::merkle_rescue_state(0)] - current[batch_cols::merkle_output(0)]);
    idx += 1;
    result[idx] = is_output_row * is_merkle * (current[batch_cols::merkle_rescue_state(1)] - current[batch_cols::merkle_output(1)]);
    idx += 1;
    result[idx] = is_output_row * is_merkle * (current[batch_cols::merkle_rescue_state(2)] - current[batch_cols::merkle_output(2)]);
    idx += 1;
    result[idx] = is_output_row * is_merkle * (current[batch_cols::merkle_rescue_state(3)] - current[batch_cols::merkle_output(3)]);
    idx += 1;

    debug_assert_eq!(idx, NUM_MERKLE_CONSTRAINTS);
    idx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constraint_count() {
        assert_eq!(NUM_MERKLE_CONSTRAINTS, 47);
    }
}
