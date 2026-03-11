//! Merkle tree and state-root finalization constraints.
//!
//! This module constrains hash rows in the Merkle and finalize phases:
//! - phase/phase-row/phase-index structural checks
//! - Rescue-Prime transition checks on each hash step row
//! - hash input/output binding for all hash rows

use crate::air::trace_layout::{batch_cols, AMOUNT_STREAM_LANE_TAGS, MERKLE_LINK_GAMMA};
use ves_stark_primitives::{
    felt_from_u64,
    rescue::{MDS, MDS_INV, STATE_WIDTH as RESCUE_STATE_WIDTH},
    Felt,
};
use winter_math::FieldElement;

/// Number of constraints produced by `evaluate_merkle_constraints`.
pub const NUM_MERKLE_CONSTRAINTS: usize = 177;

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

    let is_leaf = current[batch_cols::IS_LEAF_ROW];
    let is_leaf_hash = current[batch_cols::IS_LEAF_HASH_ROW];
    let is_commit = current[batch_cols::IS_COMMITMENT_HASH_ROW];
    let is_merkle = current[batch_cols::IS_MERKLE_ROW];
    let is_finalize = current[batch_cols::IS_FINALIZE_HASH];
    let is_pair_hash = is_commit + is_merkle;
    let is_hash_row = is_leaf_hash + is_pair_hash + is_finalize;

    let phase = current[batch_cols::BATCH_PHASE];
    let event_row = current[batch_cols::EVENT_ROW];
    let event_index = current[batch_cols::EVENT_INDEX];
    let num_events = current[batch_cols::NUM_EVENTS];
    let merkle_level = current[batch_cols::MERKLE_LEVEL];
    let merkle_node_index = current[batch_cols::MERKLE_NODE_INDEX];
    let merkle_level_size = current[batch_cols::MERKLE_LEVEL_SIZE];

    let rescue_active = periodic_values[PERIODIC_RESCUE_ACTIVE_IDX];
    let rescue_init = periodic_values[PERIODIC_RESCUE_INIT_IDX];
    let rescue_is_forward = periodic_values[PERIODIC_RESCUE_IS_FORWARD_IDX];

    let mut round_const = [E::ZERO; RESCUE_STATE_WIDTH];
    for i in 0..RESCUE_STATE_WIDTH {
        round_const[i] = periodic_values[PERIODIC_RESCUE_CONST_START_IDX + i];
    }

    let is_hash_row_active = is_hash_row * rescue_active;
    let is_output_row = is_hash_row * (E::ONE - rescue_active);
    let is_commit_output = is_commit * (E::ONE - rescue_active);
    let is_final_merkle_row = is_merkle * (E::ONE - next[batch_cols::IS_MERKLE_ROW]);
    let is_merkle_output = is_merkle * (E::ONE - rescue_active);
    let is_merkle_init = is_merkle * rescue_init;
    let is_commit_init = is_commit * rescue_init;
    let not_last_in_level = merkle_level_size - merkle_node_index - E::ONE;
    let boundary_step = next[batch_cols::MERKLE_NODE_INDEX] - merkle_node_index - E::ONE;
    let non_root_level = merkle_level_size - E::ONE;
    let not_last_real_event = num_events - merkle_node_index - E::ONE;
    let commit_boundary = is_commit_output * boundary_step;
    let gamma = E::from(felt_from_u64(MERKLE_LINK_GAMMA));
    let gamma_sq = gamma * gamma;

    // 1) Leaf rows are in phase 1.
    result[idx] = is_leaf * (phase - E::ONE);
    idx += 1;

    // 2) Commitment-hash rows are in phase 3.
    let three = felt_to_ext::<E>(3);
    result[idx] = is_commit * (phase - three);
    idx += 1;

    // 3) Merkle rows are in phase 4.
    let four = felt_to_ext::<E>(4);
    result[idx] = is_merkle * (phase - four);
    idx += 1;

    // 4) Finalize rows are in phase 5.
    let five = felt_to_ext::<E>(5);
    result[idx] = is_finalize * (phase - five);
    idx += 1;

    // 5-8) Phase flags are binary.
    result[idx] = is_leaf * (E::ONE - is_leaf);
    idx += 1;
    result[idx] = is_commit * (E::ONE - is_commit);
    idx += 1;
    result[idx] = is_finalize * (E::ONE - is_finalize);
    idx += 1;
    result[idx] = is_merkle * (E::ONE - is_merkle);
    idx += 1;

    // 9-14) Phase flags are mutually exclusive.
    result[idx] = is_leaf * is_commit;
    idx += 1;
    result[idx] = is_leaf * is_merkle;
    idx += 1;
    result[idx] = is_leaf * is_finalize;
    idx += 1;
    result[idx] = is_commit * is_merkle;
    idx += 1;
    result[idx] = is_commit * is_finalize;
    idx += 1;
    result[idx] = is_merkle * is_finalize;
    idx += 1;

    // 15-18) Leaf / Commit / Merkle / Finalize rows are on row zero.
    result[idx] = is_leaf * event_row;
    idx += 1;
    result[idx] = is_commit * event_row;
    idx += 1;
    result[idx] = is_merkle * event_row;
    idx += 1;
    result[idx] = is_finalize * event_row;
    idx += 1;

    // 19-22) These rows happen only after all events are done.
    result[idx] = is_leaf * (event_index - num_events);
    idx += 1;
    result[idx] = is_commit * (event_index - num_events);
    idx += 1;
    result[idx] = is_merkle * (event_index - num_events);
    idx += 1;
    result[idx] = is_finalize * (event_index - num_events);
    idx += 1;

    // 16-17) Rescue periodic selectors only activate on Merkle/finalize rows.
    result[idx] = rescue_active * (is_hash_row - E::ONE);
    idx += 1;
    result[idx] = rescue_init * (is_hash_row - E::ONE);
    idx += 1;

    // 25) Level-0 leaf rows must use Merkle level 0.
    result[idx] = is_leaf * merkle_level;
    idx += 1;

    // 26) Non-terminal leaf rows stay in the leaf phase.
    result[idx] = is_leaf * not_last_in_level * (next[batch_cols::IS_LEAF_ROW] - E::ONE);
    idx += 1;

    // 27-28) Consecutive leaf rows keep level size fixed and increment node index.
    result[idx] = is_leaf
        * next[batch_cols::IS_LEAF_ROW]
        * (next[batch_cols::MERKLE_NODE_INDEX] - merkle_node_index - E::ONE);
    idx += 1;
    result[idx] = is_leaf
        * next[batch_cols::IS_LEAF_ROW]
        * (next[batch_cols::MERKLE_LEVEL_SIZE] - merkle_level_size);
    idx += 1;

    // 29-32) The last leaf row transitions into the first leaf-hash segment.
    let leaf_boundary = is_leaf * boundary_step;
    result[idx] = leaf_boundary * (next[batch_cols::IS_LEAF_HASH_ROW] - E::ONE);
    idx += 1;
    result[idx] = leaf_boundary * next[batch_cols::MERKLE_LEVEL];
    idx += 1;
    result[idx] = leaf_boundary * next[batch_cols::MERKLE_NODE_INDEX];
    idx += 1;
    result[idx] = leaf_boundary * (next[batch_cols::MERKLE_LEVEL_SIZE] - merkle_level_size);
    idx += 1;

    // 33) Commitment rows use chunk/level 0.
    result[idx] = is_commit * merkle_level;
    idx += 1;

    // 34-37) Commitment active rows stay within the same hash segment.
    result[idx] = is_commit * rescue_active * (next[batch_cols::IS_COMMITMENT_HASH_ROW] - E::ONE);
    idx += 1;
    result[idx] = is_commit * rescue_active * next[batch_cols::MERKLE_LEVEL];
    idx += 1;
    result[idx] =
        is_commit * rescue_active * (next[batch_cols::MERKLE_NODE_INDEX] - merkle_node_index);
    idx += 1;
    result[idx] =
        is_commit * rescue_active * (next[batch_cols::MERKLE_LEVEL_SIZE] - merkle_level_size);
    idx += 1;

    // 38-41) Non-terminal commitment output rows advance to the next event hash segment.
    result[idx] = is_commit_output
        * not_last_real_event
        * (next[batch_cols::IS_COMMITMENT_HASH_ROW] - E::ONE);
    idx += 1;
    result[idx] = is_commit_output * not_last_real_event * next[batch_cols::MERKLE_LEVEL];
    idx += 1;
    result[idx] = is_commit_output
        * not_last_real_event
        * (next[batch_cols::MERKLE_NODE_INDEX] - merkle_node_index - E::ONE);
    idx += 1;
    result[idx] = is_commit_output
        * not_last_real_event
        * (next[batch_cols::MERKLE_LEVEL_SIZE] - merkle_level_size);
    idx += 1;

    // 42-45) The last commitment output row transitions into the first internal Merkle level.
    let commit_boundary_non_root = commit_boundary * non_root_level;
    result[idx] = commit_boundary_non_root * (next[batch_cols::IS_MERKLE_ROW] - E::ONE);
    idx += 1;
    result[idx] = commit_boundary_non_root * (next[batch_cols::MERKLE_LEVEL] - E::ONE);
    idx += 1;
    result[idx] = commit_boundary_non_root * next[batch_cols::MERKLE_NODE_INDEX];
    idx += 1;
    result[idx] = commit_boundary_non_root
        * (felt_to_ext::<E>(2) * next[batch_cols::MERKLE_LEVEL_SIZE] - merkle_level_size);
    idx += 1;

    // 46-49) Single-leaf batches skip the internal Merkle phase and go directly to finalize.
    let mut commit_single_leaf_selector = is_commit_output;
    for size in [2u64, 4, 8, 16, 32, 64, 128] {
        commit_single_leaf_selector *= merkle_level_size - felt_to_ext::<E>(size);
    }
    result[idx] = commit_single_leaf_selector * (next[batch_cols::IS_FINALIZE_HASH] - E::ONE);
    idx += 1;
    result[idx] = commit_single_leaf_selector * next[batch_cols::MERKLE_LEVEL];
    idx += 1;
    result[idx] = commit_single_leaf_selector * next[batch_cols::MERKLE_NODE_INDEX];
    idx += 1;
    result[idx] = commit_single_leaf_selector * next[batch_cols::MERKLE_LEVEL_SIZE];
    idx += 1;

    // 50-53) Merkle active rows stay within the same node segment.
    result[idx] = is_merkle * rescue_active * (next[batch_cols::IS_MERKLE_ROW] - E::ONE);
    idx += 1;
    result[idx] = is_merkle * rescue_active * (next[batch_cols::MERKLE_LEVEL] - merkle_level);
    idx += 1;
    result[idx] =
        is_merkle * rescue_active * (next[batch_cols::MERKLE_NODE_INDEX] - merkle_node_index);
    idx += 1;
    result[idx] =
        is_merkle * rescue_active * (next[batch_cols::MERKLE_LEVEL_SIZE] - merkle_level_size);
    idx += 1;

    // 54-57) Non-terminal Merkle output rows advance to the next node in the same level.
    result[idx] = is_merkle_output * not_last_in_level * (next[batch_cols::IS_MERKLE_ROW] - E::ONE);
    idx += 1;
    result[idx] =
        is_merkle_output * not_last_in_level * (next[batch_cols::MERKLE_LEVEL] - merkle_level);
    idx += 1;
    result[idx] = is_merkle_output
        * not_last_in_level
        * (next[batch_cols::MERKLE_NODE_INDEX] - merkle_node_index - E::ONE);
    idx += 1;
    result[idx] = is_merkle_output
        * not_last_in_level
        * (next[batch_cols::MERKLE_LEVEL_SIZE] - merkle_level_size);
    idx += 1;

    // 58-61) Non-root Merkle boundaries transition into the next Merkle level.
    let boundary_non_root = is_merkle_output * boundary_step * non_root_level;
    result[idx] = boundary_non_root * (next[batch_cols::IS_MERKLE_ROW] - E::ONE);
    idx += 1;
    result[idx] = boundary_non_root * (next[batch_cols::MERKLE_LEVEL] - merkle_level - E::ONE);
    idx += 1;
    result[idx] = boundary_non_root * next[batch_cols::MERKLE_NODE_INDEX];
    idx += 1;
    result[idx] = boundary_non_root
        * (felt_to_ext::<E>(2) * next[batch_cols::MERKLE_LEVEL_SIZE] - merkle_level_size);
    idx += 1;

    let mut curr_state = [E::ZERO; RESCUE_STATE_WIDTH];
    let mut next_state = [E::ZERO; RESCUE_STATE_WIDTH];
    let rescue_state_start = batch_cols::MERKLE_RESCUE_STATE_START;
    let rescue_state_end = rescue_state_start + RESCUE_STATE_WIDTH;
    curr_state.copy_from_slice(&current[rescue_state_start..rescue_state_end]);
    next_state.copy_from_slice(&next[rescue_state_start..rescue_state_end]);

    // 38-49) Rescue permutation transitions on active hash rows.
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

    // 50-61) Hash initialization.
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
        let expected = is_pair_hash * merkle_input + is_finalize * finalize_input;

        result[idx] = rescue_init * (is_pair_hash + is_finalize) * (curr_state[i] - expected);
        idx += 1;
    }

    // 62-65) Final Merkle row must match event-tree root.
    for i in 0..4 {
        result[idx] = is_final_merkle_row
            * (current[batch_cols::merkle_output(i)] - current[batch_cols::event_tree_root(i)]);
        idx += 1;
    }

    // 66-69) Single-leaf batches have no internal Merkle rows, so the lone leaf must equal the root.
    let mut leaf_single_leaf_selector = is_leaf;
    for size in [2u64, 4, 8, 16, 32, 64, 128] {
        leaf_single_leaf_selector *= merkle_level_size - felt_to_ext::<E>(size);
    }
    for i in 0..4 {
        result[idx] = leaf_single_leaf_selector
            * (current[batch_cols::merkle_output(i)] - current[batch_cols::event_tree_root(i)]);
        idx += 1;
    }

    // 70-73) Output row for finalize hash equals new state root.
    result[idx] = is_output_row
        * is_finalize
        * (current[batch_cols::merkle_rescue_state(0)] - current[batch_cols::new_state_root(0)]);
    idx += 1;
    result[idx] = is_output_row
        * is_finalize
        * (current[batch_cols::merkle_rescue_state(1)] - current[batch_cols::new_state_root(1)]);
    idx += 1;
    result[idx] = is_output_row
        * is_finalize
        * (current[batch_cols::merkle_rescue_state(2)] - current[batch_cols::new_state_root(2)]);
    idx += 1;
    result[idx] = is_output_row
        * is_finalize
        * (current[batch_cols::merkle_rescue_state(3)] - current[batch_cols::new_state_root(3)]);
    idx += 1;

    // 74-77) Active output rows bind state to event-tree node output / final root.
    result[idx] = is_output_row
        * is_pair_hash
        * (current[batch_cols::merkle_rescue_state(0)] - current[batch_cols::merkle_output(0)]);
    idx += 1;
    result[idx] = is_output_row
        * is_pair_hash
        * (current[batch_cols::merkle_rescue_state(1)] - current[batch_cols::merkle_output(1)]);
    idx += 1;
    result[idx] = is_output_row
        * is_pair_hash
        * (current[batch_cols::merkle_rescue_state(2)] - current[batch_cols::merkle_output(2)]);
    idx += 1;
    result[idx] = is_output_row
        * is_pair_hash
        * (current[batch_cols::merkle_rescue_state(3)] - current[batch_cols::merkle_output(3)]);
    idx += 1;

    // 78-89) Leaf-level linkage accumulators.
    for i in 0..4 {
        result[idx] = is_leaf
            * (next[batch_cols::merkle_prev_level_acc(i)]
                - (current[batch_cols::merkle_prev_level_acc(i)] * gamma
                    + current[batch_cols::merkle_output(i)]));
        idx += 1;
    }
    for i in 0..4 {
        result[idx] = is_leaf * next[batch_cols::merkle_consumed_level_acc(i)];
        idx += 1;
    }
    for i in 0..4 {
        result[idx] = is_leaf * next[batch_cols::merkle_curr_level_acc(i)];
        idx += 1;
    }

    // 114-117) Commitment rows keep the leaf-level accumulator constant.
    for i in 0..4 {
        result[idx] = is_commit
            * (next[batch_cols::merkle_prev_level_acc(i)]
                - current[batch_cols::merkle_prev_level_acc(i)]);
        idx += 1;
    }

    // 118-129) Previous-level accumulator carry / transfer.
    for i in 0..4 {
        result[idx] = is_merkle
            * rescue_active
            * (next[batch_cols::merkle_prev_level_acc(i)]
                - current[batch_cols::merkle_prev_level_acc(i)]);
        idx += 1;
    }
    for i in 0..4 {
        result[idx] = is_merkle_output
            * not_last_in_level
            * (next[batch_cols::merkle_prev_level_acc(i)]
                - current[batch_cols::merkle_prev_level_acc(i)]);
        idx += 1;
    }
    for i in 0..4 {
        result[idx] = boundary_non_root
            * (next[batch_cols::merkle_prev_level_acc(i)]
                - (current[batch_cols::merkle_curr_level_acc(i)] * gamma
                    + current[batch_cols::merkle_output(i)]));
        idx += 1;
    }

    // 130-141) Current-level consumed accumulator.
    for i in 0..4 {
        result[idx] = is_merkle_init
            * (next[batch_cols::merkle_consumed_level_acc(i)]
                - (current[batch_cols::merkle_consumed_level_acc(i)] * gamma_sq
                    + current[batch_cols::merkle_left(i)] * gamma
                    + current[batch_cols::merkle_right(i)]));
        idx += 1;
    }
    for i in 0..4 {
        result[idx] = is_merkle
            * rescue_active
            * (E::ONE - rescue_init)
            * (next[batch_cols::merkle_consumed_level_acc(i)]
                - current[batch_cols::merkle_consumed_level_acc(i)]);
        idx += 1;
    }
    for i in 0..4 {
        result[idx] = is_merkle_output
            * not_last_in_level
            * (next[batch_cols::merkle_consumed_level_acc(i)]
                - current[batch_cols::merkle_consumed_level_acc(i)]);
        idx += 1;
    }

    // 142-149) Current-level produced accumulator.
    for i in 0..4 {
        result[idx] = is_merkle
            * rescue_active
            * (next[batch_cols::merkle_curr_level_acc(i)]
                - current[batch_cols::merkle_curr_level_acc(i)]);
        idx += 1;
    }
    for i in 0..4 {
        result[idx] = is_merkle_output
            * not_last_in_level
            * (next[batch_cols::merkle_curr_level_acc(i)]
                - (current[batch_cols::merkle_curr_level_acc(i)] * gamma
                    + current[batch_cols::merkle_output(i)]));
        idx += 1;
    }

    // 150-153) Level boundary: consumed children must match previous-level outputs.
    let level_boundary = is_merkle_output * boundary_step;
    for i in 0..4 {
        result[idx] = level_boundary
            * (current[batch_cols::merkle_prev_level_acc(i)]
                - current[batch_cols::merkle_consumed_level_acc(i)]);
        idx += 1;
    }

    // 154-165) Commitment accumulator must match the event segment's claimed commitments.
    for i in 0..4 {
        result[idx] = is_commit
            * rescue_active
            * (next[batch_cols::merkle_curr_level_acc(i)]
                - current[batch_cols::merkle_curr_level_acc(i)]);
        idx += 1;
    }
    for i in 0..4 {
        result[idx] = is_commit_output
            * not_last_real_event
            * (next[batch_cols::merkle_curr_level_acc(i)]
                - (current[batch_cols::merkle_curr_level_acc(i)] * gamma
                    + current[batch_cols::merkle_output(i)]));
        idx += 1;
    }
    for i in 0..4 {
        result[idx] = commit_boundary
            * (current[batch_cols::merkle_curr_level_acc(i)] * gamma
                + current[batch_cols::merkle_output(i)]
                - next[batch_cols::event_commitment_acc(i)]);
        idx += 1;
    }

    // 166-171) Commitment rows also bind the streamed amount limbs.
    for i in 0..2 {
        result[idx] = is_commit
            * rescue_active
            * (next[batch_cols::merkle_consumed_level_acc(i)]
                - current[batch_cols::merkle_consumed_level_acc(i)]);
        idx += 1;
    }
    for (i, tag) in AMOUNT_STREAM_LANE_TAGS.iter().enumerate() {
        result[idx] = is_commit_output
            * not_last_real_event
            * (next[batch_cols::merkle_consumed_level_acc(i)]
                - (current[batch_cols::merkle_consumed_level_acc(i)] * gamma
                    + current[batch_cols::merkle_left(i)]
                    + felt_to_ext::<E>(*tag)));
        idx += 1;
    }
    for (i, tag) in AMOUNT_STREAM_LANE_TAGS.iter().enumerate() {
        result[idx] = commit_boundary
            * (current[batch_cols::merkle_consumed_level_acc(i)] * gamma
                + current[batch_cols::merkle_left(i)]
                + felt_to_ext::<E>(*tag)
                - next[batch_cols::event_amount_acc(i)]);
        idx += 1;
    }

    // 172-177) Amount commitments are over 64-bit amounts, so limbs 2..7 are zero on init rows.
    result[idx] = is_commit_init * current[batch_cols::merkle_left(2)];
    idx += 1;
    result[idx] = is_commit_init * current[batch_cols::merkle_left(3)];
    idx += 1;
    for i in 0..4 {
        result[idx] = is_commit_init * current[batch_cols::merkle_right(i)];
        idx += 1;
    }

    debug_assert_eq!(idx, NUM_MERKLE_CONSTRAINTS);
    idx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constraint_count() {
        assert_eq!(NUM_MERKLE_CONSTRAINTS, 177);
    }
}
