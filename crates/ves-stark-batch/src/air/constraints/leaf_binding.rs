//! Event-to-leaf stream binding constraints.
//!
//! These constraints ensure the leaf hashes consumed by the Merkle phase match the ordered
//! sequence claimed by the event-processing segment, and that the leaf rows expose the same
//! ordered field tuples as the event rows:
//! `(amount_commitment, event_id, policy_hash, public_inputs_hash, amount_limbs, flag)`.
//!
//! The amount-limb streams include fixed per-lane tags so batches whose amounts all fit into a
//! single 32-bit limb still produce non-degenerate trace polynomials in debug builds.

use crate::air::trace_layout::{batch_cols, AMOUNT_STREAM_LANE_TAGS, MERKLE_LINK_GAMMA};
use ves_stark_air::trace::cols as base_cols;
use ves_stark_primitives::{felt_from_u64, Felt};
use winter_math::FieldElement;

/// Number of constraints produced by `evaluate_leaf_binding_constraints`.
pub const NUM_LEAF_BINDING_CONSTRAINTS: usize = 151;

/// Evaluate event-to-leaf stream binding constraints.
pub fn evaluate_leaf_binding_constraints<E: FieldElement<BaseField = Felt>>(
    current: &[E],
    next: &[E],
    padding_gamma: E,
    amount_padding_offsets: [E; 2],
    policy_padding_offsets: [E; 8],
    result: &mut [E],
) -> usize {
    let mut idx = 0;

    let done = current[batch_cols::EVENTS_DONE];
    let not_done = E::ONE - done;
    let event_row = current[batch_cols::EVENT_ROW];
    let is_leaf = current[batch_cols::IS_LEAF_ROW];
    let merkle_level_size = current[batch_cols::MERKLE_LEVEL_SIZE];
    let merkle_node_index = current[batch_cols::MERKLE_NODE_INDEX];

    let two = E::from(felt_from_u64(2));
    let three = E::from(felt_from_u64(3));
    let row2 = event_row * (event_row - E::ONE) * (event_row - three);
    let not_row2 = event_row - two;
    let not_last_in_level = merkle_level_size - merkle_node_index - E::ONE;
    let boundary_step = next[batch_cols::MERKLE_NODE_INDEX] - merkle_node_index - E::ONE;
    let gamma = E::from(felt_from_u64(MERKLE_LINK_GAMMA));

    // Leaf-hash stream.
    for i in 0..4 {
        result[idx] = not_done
            * not_row2
            * (next[batch_cols::merkle_right(i)] - current[batch_cols::merkle_right(i)]);
        idx += 1;
    }
    for i in 0..4 {
        result[idx] = row2
            * (next[batch_cols::merkle_right(i)]
                - (current[batch_cols::merkle_right(i)] * gamma
                    + current[batch_cols::merkle_output(i)]));
        idx += 1;
    }
    for i in 0..4 {
        result[idx] = is_leaf
            * not_last_in_level
            * (next[batch_cols::merkle_right(i)] - current[batch_cols::merkle_right(i)]);
        idx += 1;
    }
    for i in 0..4 {
        result[idx] = is_leaf
            * boundary_step
            * (current[batch_cols::merkle_right(i)] * padding_gamma
                - next[batch_cols::merkle_prev_level_acc(i)]);
        idx += 1;
    }

    // Event-side amount-commitment stream.
    for i in 0..4 {
        result[idx] = not_done
            * not_row2
            * (next[batch_cols::event_commitment_acc(i)]
                - current[batch_cols::event_commitment_acc(i)]);
        idx += 1;
    }
    for i in 0..4 {
        result[idx] = row2
            * (next[batch_cols::event_commitment_acc(i)]
                - (current[batch_cols::event_commitment_acc(i)] * gamma
                    + current[base_cols::RESCUE_STATE_START + i]));
        idx += 1;
    }

    // Event-side event-id stream.
    for i in 0..4 {
        result[idx] = not_done
            * not_row2
            * (next[batch_cols::event_id_acc(i)] - current[batch_cols::event_id_acc(i)]);
        idx += 1;
    }
    for i in 0..4 {
        result[idx] = row2
            * (next[batch_cols::event_id_acc(i)]
                - (current[batch_cols::event_id_acc(i)] * gamma
                    + current[base_cols::RESCUE_STATE_START + 4 + i]));
        idx += 1;
    }

    // Event-side policy-hash stream.
    for i in 0..8 {
        result[idx] = not_done
            * not_row2
            * (next[batch_cols::event_policy_acc(i)] - current[batch_cols::event_policy_acc(i)]);
        idx += 1;
    }
    for i in 0..8 {
        result[idx] = row2
            * (next[batch_cols::event_policy_acc(i)]
                - (current[batch_cols::event_policy_acc(i)] * gamma
                    + current[batch_cols::POLICY_HASH_START + i]));
        idx += 1;
    }

    // Event-side canonical public-input hash stream.
    for i in 0..8 {
        result[idx] = not_done
            * not_row2
            * (next[batch_cols::event_public_inputs_acc(i)]
                - current[batch_cols::event_public_inputs_acc(i)]);
        idx += 1;
    }
    for i in 0..8 {
        result[idx] = row2
            * (next[batch_cols::event_public_inputs_acc(i)]
                - (current[batch_cols::event_public_inputs_acc(i)] * gamma
                    + current[base_cols::COMPARISON_START + i]));
        idx += 1;
    }

    // Event-side amount-limb stream.
    for i in 0..2 {
        result[idx] = not_done
            * not_row2
            * (next[batch_cols::event_amount_acc(i)] - current[batch_cols::event_amount_acc(i)]);
        idx += 1;
    }
    for i in 0..2 {
        result[idx] = row2
            * (next[batch_cols::event_amount_acc(i)]
                - (current[batch_cols::event_amount_acc(i)] * gamma
                    + current[base_cols::AMOUNT_START + i]
                    + E::from(felt_from_u64(AMOUNT_STREAM_LANE_TAGS[i]))));
        idx += 1;
    }

    // Event-side compliance-flag stream.
    result[idx] = not_done
        * not_row2
        * (next[batch_cols::EVENT_FLAG_ACC] - current[batch_cols::EVENT_FLAG_ACC]);
    idx += 1;
    result[idx] = row2
        * (next[batch_cols::EVENT_FLAG_ACC]
            - (current[batch_cols::EVENT_FLAG_ACC] * gamma
                + current[batch_cols::EVENT_COMPLIANCE_FLAG]));
    idx += 1;

    // Leaf rows carry the final event-side field streams forward.
    for i in 0..4 {
        result[idx] = is_leaf
            * not_last_in_level
            * (next[batch_cols::event_commitment_acc(i)]
                - current[batch_cols::event_commitment_acc(i)]);
        idx += 1;
    }
    for i in 0..4 {
        result[idx] = is_leaf
            * not_last_in_level
            * (next[batch_cols::event_id_acc(i)] - current[batch_cols::event_id_acc(i)]);
        idx += 1;
    }
    for i in 0..8 {
        result[idx] = is_leaf
            * not_last_in_level
            * (next[batch_cols::event_policy_acc(i)] - current[batch_cols::event_policy_acc(i)]);
        idx += 1;
    }
    for i in 0..8 {
        result[idx] = is_leaf
            * not_last_in_level
            * (next[batch_cols::event_public_inputs_acc(i)]
                - current[batch_cols::event_public_inputs_acc(i)]);
        idx += 1;
    }
    for i in 0..2 {
        result[idx] = is_leaf
            * not_last_in_level
            * (next[batch_cols::event_amount_acc(i)] - current[batch_cols::event_amount_acc(i)]);
        idx += 1;
    }
    result[idx] = is_leaf
        * not_last_in_level
        * (next[batch_cols::EVENT_FLAG_ACC] - current[batch_cols::EVENT_FLAG_ACC]);
    idx += 1;

    // Leaf-side field streams.
    for i in 0..4 {
        result[idx] = is_leaf
            * (next[batch_cols::leaf_commitment_acc(i)]
                - (current[batch_cols::leaf_commitment_acc(i)] * gamma
                    + current[base_cols::RESCUE_STATE_START + i]));
        idx += 1;
    }
    for i in 0..4 {
        result[idx] = is_leaf
            * (next[batch_cols::leaf_id_acc(i)]
                - (current[batch_cols::leaf_id_acc(i)] * gamma
                    + current[base_cols::RESCUE_STATE_START + 4 + i]));
        idx += 1;
    }
    for i in 0..8 {
        result[idx] = is_leaf
            * (next[batch_cols::leaf_policy_acc(i)]
                - (current[batch_cols::leaf_policy_acc(i)] * gamma
                    + current[batch_cols::POLICY_HASH_START + i]));
        idx += 1;
    }
    for i in 0..8 {
        result[idx] = is_leaf
            * (next[batch_cols::leaf_public_inputs_acc(i)]
                - (current[batch_cols::leaf_public_inputs_acc(i)] * gamma
                    + current[base_cols::COMPARISON_START + i]));
        idx += 1;
    }
    for i in 0..2 {
        result[idx] = is_leaf
            * (next[batch_cols::leaf_amount_acc(i)]
                - (current[batch_cols::leaf_amount_acc(i)] * gamma
                    + current[base_cols::AMOUNT_START + i]
                    + E::from(felt_from_u64(AMOUNT_STREAM_LANE_TAGS[i]))));
        idx += 1;
    }
    result[idx] = is_leaf
        * (next[batch_cols::LEAF_FLAG_ACC]
            - (current[batch_cols::LEAF_FLAG_ACC] * gamma
                + current[batch_cols::EVENT_COMPLIANCE_FLAG]));
    idx += 1;

    // Boundary equality between the event-side and leaf-side streams, adjusted for padded leaves.
    for i in 0..4 {
        result[idx] = is_leaf
            * boundary_step
            * (current[batch_cols::event_commitment_acc(i)] * padding_gamma
                - next[batch_cols::leaf_commitment_acc(i)]);
        idx += 1;
    }
    for i in 0..4 {
        result[idx] = is_leaf
            * boundary_step
            * (current[batch_cols::event_id_acc(i)] * padding_gamma
                - next[batch_cols::leaf_id_acc(i)]);
        idx += 1;
    }
    for i in 0..8 {
        result[idx] = is_leaf
            * boundary_step
            * (current[batch_cols::event_policy_acc(i)] * padding_gamma
                + policy_padding_offsets[i]
                - next[batch_cols::leaf_policy_acc(i)]);
        idx += 1;
    }
    for i in 0..8 {
        result[idx] = is_leaf
            * boundary_step
            * (current[batch_cols::event_public_inputs_acc(i)] * padding_gamma
                - next[batch_cols::leaf_public_inputs_acc(i)]);
        idx += 1;
    }
    for i in 0..2 {
        result[idx] = is_leaf
            * boundary_step
            * (current[batch_cols::event_amount_acc(i)] * padding_gamma
                + amount_padding_offsets[i]
                - next[batch_cols::leaf_amount_acc(i)]);
        idx += 1;
    }
    result[idx] = is_leaf
        * boundary_step
        * (current[batch_cols::EVENT_FLAG_ACC] * padding_gamma - next[batch_cols::LEAF_FLAG_ACC]);
    idx += 1;

    debug_assert_eq!(idx, NUM_LEAF_BINDING_CONSTRAINTS);
    idx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constraint_count() {
        assert_eq!(NUM_LEAF_BINDING_CONSTRAINTS, 151);
    }
}
