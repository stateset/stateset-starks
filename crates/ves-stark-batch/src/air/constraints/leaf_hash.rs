//! In-circuit leaf-hash constraints.
//!
//! Each real event leaf hashes a 25-element preimage:
//! `event_id || amount_commitment || policy_hash || public_inputs_hash || compliance_flag`.
//! With Rescue's rate of 8, this requires 4 sponge absorptions / permutations.

use crate::air::constraints::merkle::PERIODIC_RESCUE_ACTIVE_IDX;
use crate::air::trace_layout::{batch_cols, MERKLE_LINK_GAMMA};
use ves_stark_primitives::{felt_from_u64, Felt};
use winter_math::FieldElement;

/// Number of constraints produced by `evaluate_leaf_hash_constraints`.
pub const NUM_LEAF_HASH_CONSTRAINTS: usize = 104;

#[inline]
fn felt_to_ext<E: FieldElement<BaseField = Felt>>(value: u64) -> E {
    E::from(felt_from_u64(value))
}

/// Evaluate leaf-hash phase constraints.
pub fn evaluate_leaf_hash_constraints<E: FieldElement<BaseField = Felt>>(
    current: &[E],
    next: &[E],
    periodic_values: &[E],
    padding_gamma: E,
    result: &mut [E],
) -> usize {
    let mut idx = 0;

    let is_leaf = current[batch_cols::IS_LEAF_ROW];
    let is_leaf_hash = current[batch_cols::IS_LEAF_HASH_ROW];
    let is_commit = current[batch_cols::IS_COMMITMENT_HASH_ROW];
    let is_merkle = current[batch_cols::IS_MERKLE_ROW];
    let is_finalize = current[batch_cols::IS_FINALIZE_HASH];

    let phase = current[batch_cols::BATCH_PHASE];
    let event_row = current[batch_cols::EVENT_ROW];
    let event_index = current[batch_cols::EVENT_INDEX];
    let num_events = current[batch_cols::NUM_EVENTS];
    let chunk = current[batch_cols::MERKLE_LEVEL];
    let node_index = current[batch_cols::MERKLE_NODE_INDEX];
    let level_size = current[batch_cols::MERKLE_LEVEL_SIZE];

    let rescue_active = periodic_values[PERIODIC_RESCUE_ACTIVE_IDX];
    let is_output_row = is_leaf_hash * (E::ONE - rescue_active);
    let boundary_step = next[batch_cols::MERKLE_NODE_INDEX] - node_index - E::ONE;
    let not_last_real_event = num_events - node_index - E::ONE;

    let one = E::ONE;
    let two = felt_to_ext::<E>(2);
    let three = felt_to_ext::<E>(3);
    let leaf_hash_phase = two;
    let input_len = felt_to_ext::<E>(25);
    let gamma = E::from(felt_from_u64(MERKLE_LINK_GAMMA));

    let chunk3 = is_leaf_hash * chunk * (chunk - one) * (chunk - two);
    let mid_chunk_output = is_output_row * (chunk - three);
    let chunk0_output = is_output_row * (chunk - one) * (chunk - two) * (chunk - three);
    let chunk1_output = is_output_row * chunk * (chunk - two) * (chunk - three);
    let chunk2_output = is_output_row * chunk * (chunk - one) * (chunk - three);
    let final_chunk_output = is_output_row * chunk * (chunk - one) * (chunk - two);
    let final_chunk_non_last = final_chunk_output * not_last_real_event;
    let final_chunk_boundary = final_chunk_output * boundary_step;
    let leaf_boundary = is_leaf * boundary_step;

    // 1-8) Phase/flag sanity.
    result[idx] = is_leaf_hash * (phase - leaf_hash_phase);
    idx += 1;
    result[idx] = is_leaf_hash * (one - is_leaf_hash);
    idx += 1;
    result[idx] = is_leaf_hash * is_leaf;
    idx += 1;
    result[idx] = is_leaf_hash * is_commit;
    idx += 1;
    result[idx] = is_leaf_hash * is_merkle;
    idx += 1;
    result[idx] = is_leaf_hash * is_finalize;
    idx += 1;
    result[idx] = is_leaf_hash * event_row;
    idx += 1;
    result[idx] = is_leaf_hash * (event_index - num_events);
    idx += 1;

    // 9) Chunk index is in {0,1,2,3}.
    result[idx] = is_leaf_hash * chunk * (chunk - one) * (chunk - two) * (chunk - three);
    idx += 1;

    // 10-13) Active rows stay inside the same chunk.
    result[idx] = is_leaf_hash * rescue_active * (next[batch_cols::IS_LEAF_HASH_ROW] - one);
    idx += 1;
    result[idx] = is_leaf_hash * rescue_active * (next[batch_cols::MERKLE_LEVEL] - chunk);
    idx += 1;
    result[idx] = is_leaf_hash * rescue_active * (next[batch_cols::MERKLE_NODE_INDEX] - node_index);
    idx += 1;
    result[idx] = is_leaf_hash * rescue_active * (next[batch_cols::MERKLE_LEVEL_SIZE] - level_size);
    idx += 1;

    // 14-17) Chunk 0 / 1 / 2 output rows advance to the next chunk of the same leaf.
    result[idx] = mid_chunk_output * (next[batch_cols::IS_LEAF_HASH_ROW] - one);
    idx += 1;
    result[idx] = mid_chunk_output * (next[batch_cols::MERKLE_LEVEL] - chunk - one);
    idx += 1;
    result[idx] = mid_chunk_output * (next[batch_cols::MERKLE_NODE_INDEX] - node_index);
    idx += 1;
    result[idx] = mid_chunk_output * (next[batch_cols::MERKLE_LEVEL_SIZE] - level_size);
    idx += 1;

    // 18-21) Final chunk output rows advance to the next real leaf when present.
    result[idx] = final_chunk_non_last * (next[batch_cols::IS_LEAF_HASH_ROW] - one);
    idx += 1;
    result[idx] = final_chunk_non_last * next[batch_cols::MERKLE_LEVEL];
    idx += 1;
    result[idx] = final_chunk_non_last * (next[batch_cols::MERKLE_NODE_INDEX] - node_index - one);
    idx += 1;
    result[idx] = final_chunk_non_last * (next[batch_cols::MERKLE_LEVEL_SIZE] - level_size);
    idx += 1;

    // 22-25) The last real leaf transitions into the commitment-hash phase.
    result[idx] = final_chunk_boundary * (next[batch_cols::IS_COMMITMENT_HASH_ROW] - one);
    idx += 1;
    result[idx] = final_chunk_boundary * next[batch_cols::MERKLE_LEVEL];
    idx += 1;
    result[idx] = final_chunk_boundary * next[batch_cols::MERKLE_NODE_INDEX];
    idx += 1;
    result[idx] = final_chunk_boundary * (next[batch_cols::MERKLE_LEVEL_SIZE] - level_size);
    idx += 1;

    // 26-37) Leaf -> leaf-hash boundary initializes the first sponge chunk.
    for i in 0..4 {
        result[idx] = leaf_boundary
            * (next[batch_cols::merkle_rescue_state(i)] - next[batch_cols::merkle_left(i)]);
        idx += 1;
    }
    for i in 0..4 {
        result[idx] = leaf_boundary
            * (next[batch_cols::merkle_rescue_state(4 + i)] - next[batch_cols::merkle_right(i)]);
        idx += 1;
    }
    result[idx] = leaf_boundary * (next[batch_cols::merkle_rescue_state(8)] - input_len);
    idx += 1;
    for i in 9..12 {
        result[idx] = leaf_boundary * next[batch_cols::merkle_rescue_state(i)];
        idx += 1;
    }

    // 38-49) Chunk 0 output feeds chunk 1 by absorbing policy-hash lanes.
    for i in 0..4 {
        result[idx] = chunk0_output
            * (next[batch_cols::merkle_rescue_state(i)]
                - (current[batch_cols::merkle_rescue_state(i)] + next[batch_cols::merkle_left(i)]));
        idx += 1;
    }
    for i in 0..4 {
        result[idx] = chunk0_output
            * (next[batch_cols::merkle_rescue_state(4 + i)]
                - (current[batch_cols::merkle_rescue_state(4 + i)]
                    + next[batch_cols::merkle_right(i)]));
        idx += 1;
    }
    for i in 8..12 {
        result[idx] = chunk0_output
            * (next[batch_cols::merkle_rescue_state(i)]
                - current[batch_cols::merkle_rescue_state(i)]);
        idx += 1;
    }

    // 50-61) Chunk 1 output feeds chunk 2 by absorbing public-input hash lanes.
    for i in 0..4 {
        result[idx] = chunk1_output
            * (next[batch_cols::merkle_rescue_state(i)]
                - (current[batch_cols::merkle_rescue_state(i)] + next[batch_cols::merkle_left(i)]));
        idx += 1;
    }
    for i in 0..4 {
        result[idx] = chunk1_output
            * (next[batch_cols::merkle_rescue_state(4 + i)]
                - (current[batch_cols::merkle_rescue_state(4 + i)]
                    + next[batch_cols::merkle_right(i)]));
        idx += 1;
    }
    for i in 8..12 {
        result[idx] = chunk1_output
            * (next[batch_cols::merkle_rescue_state(i)]
                - current[batch_cols::merkle_rescue_state(i)]);
        idx += 1;
    }

    // 62-73) Chunk 2 output feeds chunk 3 by absorbing the compliance flag.
    result[idx] = chunk2_output
        * (next[batch_cols::merkle_rescue_state(0)]
            - (current[batch_cols::merkle_rescue_state(0)] + next[batch_cols::merkle_left(0)]));
    idx += 1;
    for i in 1..8 {
        result[idx] = chunk2_output
            * (next[batch_cols::merkle_rescue_state(i)]
                - current[batch_cols::merkle_rescue_state(i)]);
        idx += 1;
    }
    for i in 8..12 {
        result[idx] = chunk2_output
            * (next[batch_cols::merkle_rescue_state(i)]
                - current[batch_cols::merkle_rescue_state(i)]);
        idx += 1;
    }

    // 74-80) Chunk 3 only absorbs the flag into lane 0.
    for i in 1..4 {
        result[idx] = chunk3 * current[batch_cols::merkle_left(i)];
        idx += 1;
    }
    for i in 0..4 {
        result[idx] = chunk3 * current[batch_cols::merkle_right(i)];
        idx += 1;
    }

    // 81-84) Final chunk output must equal the claimed leaf hash.
    for i in 0..4 {
        result[idx] = final_chunk_output
            * (current[batch_cols::merkle_rescue_state(i)] - current[batch_cols::merkle_output(i)]);
        idx += 1;
    }

    // 85-88) Carry the padded-leaf accumulator from the leaf phase unchanged.
    for i in 0..4 {
        result[idx] = is_leaf_hash
            * (next[batch_cols::merkle_prev_level_acc(i)]
                - current[batch_cols::merkle_prev_level_acc(i)]);
        idx += 1;
    }

    // 89-92) Active rows do not update the derived leaf-hash accumulator.
    for i in 0..4 {
        result[idx] = is_leaf_hash
            * rescue_active
            * (next[batch_cols::merkle_curr_level_acc(i)]
                - current[batch_cols::merkle_curr_level_acc(i)]);
        idx += 1;
    }

    // 93-96) Chunk 0 / 1 / 2 outputs also keep the accumulator unchanged.
    for i in 0..4 {
        result[idx] = mid_chunk_output
            * (next[batch_cols::merkle_curr_level_acc(i)]
                - current[batch_cols::merkle_curr_level_acc(i)]);
        idx += 1;
    }

    // 97-100) Final chunk outputs append the derived leaf hash for non-terminal real leaves.
    for i in 0..4 {
        result[idx] = final_chunk_non_last
            * (next[batch_cols::merkle_curr_level_acc(i)]
                - (current[batch_cols::merkle_curr_level_acc(i)] * gamma
                    + current[batch_cols::merkle_output(i)]));
        idx += 1;
    }

    // 101-104) The last real leaf must match the padded leaf-hash stream from the leaf phase.
    for i in 0..4 {
        result[idx] = final_chunk_boundary
            * ((current[batch_cols::merkle_curr_level_acc(i)] * gamma
                + current[batch_cols::merkle_output(i)])
                * padding_gamma
                - next[batch_cols::merkle_prev_level_acc(i)]);
        idx += 1;
    }

    debug_assert_eq!(idx, NUM_LEAF_HASH_CONSTRAINTS);
    idx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constraint_count() {
        assert_eq!(NUM_LEAF_HASH_CONSTRAINTS, 104);
    }
}
