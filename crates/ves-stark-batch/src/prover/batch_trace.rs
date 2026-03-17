//! Batch trace construction
//!
//! This module builds the execution trace for batch state transition proofs.
//! The trace extends the single-event compliance trace with batch-specific columns.

use rayon::prelude::*;
use ves_stark_air::trace::cols as base_cols;
use ves_stark_primitives::rescue::{rescue_permutation_trace, STATE_WIDTH as RESCUE_STATE_WIDTH};
use ves_stark_primitives::{felt_from_u64, Felt, FELT_ONE, FELT_ZERO};
use winter_math::FieldElement;
use winter_prover::TraceTable;

use crate::air::trace_layout::{
    batch_cols, calculate_trace_length, leaf_hash_row_count, leaf_row_count, padded_leaf_count,
    BatchPhase, AMOUNT_STREAM_LANE_TAGS, BASE_TRACE_WIDTH, BATCH_TRACE_WIDTH, COMPLIANCE_ACC_GAMMA,
    FINALIZE_ROWS, ROWS_PER_COMMITMENT_HASH, ROWS_PER_EVENT, ROWS_PER_LEAF_HASH,
    ROWS_PER_MERKLE_NODE,
};
use crate::error::BatchError;
use crate::prover::witness::{BatchEventWitness, BatchWitness};
use crate::state::{BatchStateRoot, EventLeaf, EventMerkleTree};

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E3779B97F4A7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D049BB133111EB);
    x ^ (x >> 31)
}

/// Deterministic "filler" bit used for binary columns that would otherwise be constant in
/// some executions (e.g. when all events are compliant).
///
/// The AIR only reads `EVENT_COMPLIANCE_FLAG` on a specific row within each event (where the
/// accumulator update is enforced). On other rows, any binary value is valid, and we fill
/// with a pseudo-random pattern to avoid degenerate trace polynomials in debug builds.
fn filler_bit(seed: u64) -> Felt {
    if splitmix64(seed) & 1 == 1 {
        FELT_ONE
    } else {
        FELT_ZERO
    }
}

/// Decompose a field element (representing a u32 limb) into 32 bits
fn decompose_to_bits(limb: Felt) -> [Felt; 32] {
    let mut bits = [FELT_ZERO; 32];
    let value = limb.as_int() as u32;

    for (i, bit) in bits.iter_mut().enumerate() {
        if (value >> i) & 1 == 1 {
            *bit = FELT_ONE;
        }
    }

    bits
}

/// Compute the 2-limb subtraction witness for `amount <= effective_limit`.
///
/// The witness remains well-defined for both compliant and non-compliant events:
/// the final borrow bit is `0` when the event is compliant and `1` otherwise.
fn compute_subtraction_witness(
    amount_limbs: &[Felt; 8],
    limit_limbs: &[Felt; 8],
) -> ([Felt; 2], [Felt; 2]) {
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

    (
        [felt_from_u64(diff0), felt_from_u64(diff1)],
        [felt_from_u64(borrow0), felt_from_u64(borrow1)],
    )
}

#[derive(Clone, Copy, Debug, Default)]
struct LeafFieldAccumulators {
    commitment: [Felt; 4],
    event_id: [Felt; 4],
    policy_hash: [Felt; 8],
    public_inputs_hash: [Felt; 8],
    amount: [Felt; 2],
    flag: Felt,
}

impl LeafFieldAccumulators {
    fn append_leaf(&mut self, leaf: &EventLeaf, amount_limbs: &[Felt; 8], gamma: Felt) {
        for i in 0..4 {
            self.commitment[i] = self.commitment[i] * gamma + leaf.amount_commitment[i];
            self.event_id[i] = self.event_id[i] * gamma + leaf.event_id[i];
        }
        for i in 0..8 {
            self.policy_hash[i] = self.policy_hash[i] * gamma + leaf.policy_hash[i];
            self.public_inputs_hash[i] =
                self.public_inputs_hash[i] * gamma + leaf.public_inputs_hash[i];
        }
        for (i, tag) in AMOUNT_STREAM_LANE_TAGS.iter().enumerate() {
            self.amount[i] = self.amount[i] * gamma + amount_limbs[i] + felt_from_u64(*tag);
        }
        self.flag = self.flag * gamma + leaf.compliance_flag;
    }

    fn append_padding(&mut self, gamma: Felt, policy_hash: &[Felt; 8]) {
        for (commitment_lane, event_id_lane) in
            self.commitment.iter_mut().zip(self.event_id.iter_mut())
        {
            *commitment_lane *= gamma;
            *event_id_lane *= gamma;
        }
        for ((policy_lane, public_inputs_lane), policy_hash_lane) in self
            .policy_hash
            .iter_mut()
            .zip(self.public_inputs_hash.iter_mut())
            .zip(policy_hash.iter())
        {
            *policy_lane = *policy_lane * gamma + *policy_hash_lane;
            *public_inputs_lane *= gamma;
        }
        for (i, tag) in AMOUNT_STREAM_LANE_TAGS.iter().enumerate() {
            self.amount[i] = self.amount[i] * gamma + felt_from_u64(*tag);
        }
        self.flag *= gamma;
    }
}

/// Builder for batch execution traces
pub struct BatchTraceBuilder {
    /// The batch witness
    witness: BatchWitness,

    /// Trace length (will be computed)
    trace_length: usize,
}

impl BatchTraceBuilder {
    /// Create a new batch trace builder
    pub fn new(witness: BatchWitness) -> Self {
        let trace_length = calculate_trace_length(witness.num_events());

        Self {
            witness,
            trace_length,
        }
    }

    /// Set a custom trace length (must be power of 2)
    pub fn with_trace_length(mut self, length: usize) -> Self {
        // Never allow a custom length that would truncate required rows for the configured witness.
        self.trace_length = length
            .next_power_of_two()
            .max(calculate_trace_length(self.witness.num_events()));
        self
    }

    /// Build the execution trace
    pub fn build(self) -> Result<TraceTable<Felt>, BatchError> {
        // Validate witness
        self.witness.validate()?;

        let batch_policy = self.witness.policy()?;
        let policy_limit_limbs = batch_policy
            .effective_limit_limbs()
            .map_err(|e| BatchError::InvalidWitness(format!("Invalid batch policy: {e}")))?;

        // Initialize trace columns
        let mut trace = vec![vec![FELT_ZERO; self.trace_length]; BATCH_TRACE_WIDTH];

        // Get batch-level data
        let batch_id = self.witness.batch_id_felts();
        let tenant_id = self.witness.tenant_id_felts();
        let store_id = self.witness.store_id_felts();
        let metadata_hash = self
            .witness
            .metadata
            .to_chained_rescue_hash(&self.witness.prev_state_root.root);

        // Build event Merkle tree and compute state roots
        let event_leaves: Vec<_> = self
            .witness
            .events
            .iter()
            .map(|event| event.to_event_leaf(&self.witness.policy_hash))
            .collect::<Result<Vec<_>, _>>()?;
        let event_tree = EventMerkleTree::from_leaves(event_leaves.clone())?;
        let prev_state_root = &self.witness.prev_state_root;
        let new_state_root = BatchStateRoot::compute(
            &self.witness.prev_state_root,
            &event_tree,
            &self.witness.metadata,
        );

        // Process events in parallel
        let event_traces: Vec<_> = self
            .witness
            .events
            .par_iter()
            .zip(event_leaves.par_iter())
            .map(|(event, leaf)| self.build_event_trace(event, &policy_limit_limbs, leaf))
            .collect::<Result<Vec<_>, _>>()?;

        // Fill trace with event data
        let mut current_row = 0;
        let gamma = Felt::new(COMPLIANCE_ACC_GAMMA);
        let gamma_inv_pow_n = gamma.exp(self.witness.num_events() as u64).inv();
        let mut compliance_accumulator = gamma_inv_pow_n;
        let leaf_gamma = Felt::new(crate::air::trace_layout::MERKLE_LINK_GAMMA);
        let mut event_leaf_acc = [FELT_ZERO; 4];
        let mut event_field_acc = LeafFieldAccumulators::default();
        let zero_field_acc = LeafFieldAccumulators::default();
        let junk_bit = felt_from_u64(2);
        let junk_pair = [junk_bit; 2];

        for (event_idx, event_trace) in event_traces.iter().enumerate() {
            let event = &self.witness.events[event_idx];
            let event_leaf = &event_leaves[event_idx];
            let amount_limbs = event.amount_limbs();
            let mut updated_event_leaf_acc = event_leaf_acc;
            let mut updated_event_field_acc = event_field_acc;
            updated_event_field_acc.append_leaf(event_leaf, &amount_limbs, leaf_gamma);
            for (i, leaf_hash_lane) in event_trace.leaf_hash.iter().enumerate() {
                updated_event_leaf_acc[i] =
                    updated_event_leaf_acc[i] * leaf_gamma + *leaf_hash_lane;
            }

            for row_in_event in 0..ROWS_PER_EVENT {
                let row = current_row + row_in_event;
                if row >= self.trace_length {
                    break;
                }

                // Copy base trace columns from event trace
                for (dst_col, src_col) in trace
                    .iter_mut()
                    .take(BASE_TRACE_WIDTH)
                    .zip(event_trace.base.iter())
                {
                    dst_col[row] = src_col[row_in_event];
                }

                // Set batch-specific columns
                trace[batch_cols::EVENT_INDEX][row] = felt_from_u64(event_idx as u64);
                trace[batch_cols::NUM_EVENTS][row] =
                    felt_from_u64(self.witness.num_events() as u64);
                trace[batch_cols::EVENT_ROW][row] = felt_from_u64(row_in_event as u64);
                trace[batch_cols::BATCH_PHASE][row] = BatchPhase::Event.to_felt();
                trace[batch_cols::IS_LEAF_ROW][row] = FELT_ZERO;
                trace[batch_cols::IS_LEAF_HASH_ROW][row] = FELT_ZERO;
                trace[batch_cols::IS_COMMITMENT_HASH_ROW][row] = FELT_ZERO;
                trace[batch_cols::MERKLE_LEVEL][row] = FELT_ZERO;
                trace[batch_cols::MERKLE_NODE_INDEX][row] = FELT_ZERO;
                trace[batch_cols::MERKLE_LEVEL_SIZE][row] = FELT_ZERO;
                let (row_diff, row_borrow) = match row_in_event {
                    1 => (event_trace.diff, event_trace.borrow),
                    2 => (junk_pair, event_trace.borrow),
                    _ => (junk_pair, junk_pair),
                };
                trace[batch_cols::event_diff(0)][row] = row_diff[0];
                trace[batch_cols::event_diff(1)][row] = row_diff[1];
                trace[batch_cols::event_borrow(0)][row] = row_borrow[0];
                trace[batch_cols::event_borrow(1)][row] = row_borrow[1];
                for i in 0..4 {
                    trace[batch_cols::merkle_output(i)][row] = if row_in_event == 2 {
                        event_trace.leaf_hash[i]
                    } else {
                        FELT_ZERO
                    };
                    trace[batch_cols::merkle_right(i)][row] = if row_in_event == 3 {
                        updated_event_leaf_acc[i]
                    } else {
                        event_leaf_acc[i]
                    };
                }
                write_event_field_accumulators(
                    &mut trace,
                    row,
                    if row_in_event == 3 {
                        &updated_event_field_acc
                    } else {
                        &event_field_acc
                    },
                );
                write_leaf_field_accumulators(&mut trace, row, &zero_field_acc);

                // State roots (constant)
                for i in 0..4 {
                    trace[batch_cols::prev_state_root(i)][row] = prev_state_root.root[i];
                    trace[batch_cols::new_state_root(i)][row] = new_state_root.root[i];
                    trace[batch_cols::event_tree_root(i)][row] = event_tree.root()[i];
                }

                // Update compliance accumulator at end of each event
                if row_in_event == ROWS_PER_EVENT - 1 {
                    compliance_accumulator *= gamma * event.compliance_felt();
                }
                trace[batch_cols::COMPLIANCE_ACCUMULATOR][row] = compliance_accumulator;
                trace[batch_cols::EVENT_COMPLIANCE_FLAG][row] =
                    if row_in_event == ROWS_PER_EVENT - 2 {
                        // Flag is consumed by the AIR on the transition into the last row of the event.
                        event.compliance_felt()
                    } else {
                        FELT_ONE - event.compliance_felt()
                    };

                // Metadata (constant)
                for i in 0..4 {
                    trace[batch_cols::batch_id(i)][row] = batch_id[i];
                    trace[batch_cols::metadata_hash(i)][row] = metadata_hash[i];
                }
                trace[batch_cols::TENANT_ID_START][row] = tenant_id[0];
                trace[batch_cols::TENANT_ID_START + 1][row] = tenant_id[1];
                trace[batch_cols::TENANT_ID_START + 2][row] = tenant_id[2];
                trace[batch_cols::TENANT_ID_START + 3][row] = tenant_id[3];
                trace[batch_cols::STORE_ID_START][row] = store_id[0];
                trace[batch_cols::STORE_ID_START + 1][row] = store_id[1];
                trace[batch_cols::STORE_ID_START + 2][row] = store_id[2];
                trace[batch_cols::STORE_ID_START + 3][row] = store_id[3];
                trace[batch_cols::SEQUENCE_START][row] =
                    felt_from_u64(self.witness.metadata.sequence_start);
                trace[batch_cols::SEQUENCE_END][row] =
                    felt_from_u64(self.witness.metadata.sequence_end);
                trace[batch_cols::TIMESTAMP][row] = felt_from_u64(self.witness.metadata.timestamp);

                // Policy (constant)
                for i in 0..8 {
                    trace[batch_cols::POLICY_HASH_START + i][row] = self.witness.policy_hash[i];
                }
                trace[batch_cols::POLICY_LIMIT][row] = felt_from_u64(self.witness.policy_limit);

                // Control flags
                trace[batch_cols::IS_FIRST_BATCH_ROW][row] =
                    if row == 0 { FELT_ONE } else { FELT_ZERO };
                trace[batch_cols::IS_MERKLE_ROW][row] = FELT_ZERO;
                trace[batch_cols::IS_FINALIZE_HASH][row] = FELT_ZERO;
                trace[batch_cols::MERKLE_HASH_STEP][row] = FELT_ZERO;
                trace[batch_cols::EVENTS_DONE][row] = FELT_ZERO;
                for i in 0..4 {
                    trace[batch_cols::merkle_prev_level_acc(i)][row] = FELT_ZERO;
                    trace[batch_cols::merkle_consumed_level_acc(i)][row] = FELT_ZERO;
                    trace[batch_cols::merkle_curr_level_acc(i)][row] = FELT_ZERO;
                }
            }

            event_leaf_acc = updated_event_leaf_acc;
            event_field_acc = updated_event_field_acc;
            current_row += ROWS_PER_EVENT;
        }

        // Fill explicit leaf rows (level 0 of the event tree).
        let (current_row_after_leaves, leaf_field_acc) = self.fill_leaf_trace(
            &mut trace,
            current_row,
            &event_leaves,
            &event_tree,
            prev_state_root,
            &new_state_root,
            compliance_accumulator,
            &event_leaf_acc,
            &event_field_acc,
            &batch_id,
            &tenant_id,
            &store_id,
            &metadata_hash,
        );
        current_row = current_row_after_leaves;

        let mut initial_leaf_level_acc = [FELT_ZERO; 4];
        if current_row > 0 {
            for (i, slot) in initial_leaf_level_acc.iter_mut().enumerate() {
                *slot = trace[batch_cols::merkle_prev_level_acc(i)][current_row - 1] * leaf_gamma
                    + trace[batch_cols::merkle_output(i)][current_row - 1];
            }
        }

        current_row = self.fill_leaf_hash_trace(
            &mut trace,
            current_row,
            &event_leaves,
            prev_state_root,
            &new_state_root,
            &event_tree,
            compliance_accumulator,
            &initial_leaf_level_acc,
            &event_field_acc,
            &leaf_field_acc,
            &batch_id,
            &tenant_id,
            &store_id,
            &metadata_hash,
        );

        // Fill amount-commitment hash rows for real events.
        current_row = self.fill_commitment_hash_trace(
            &mut trace,
            current_row,
            prev_state_root,
            &new_state_root,
            &event_tree,
            compliance_accumulator,
            &initial_leaf_level_acc,
            &event_field_acc,
            &leaf_field_acc,
            &batch_id,
            &tenant_id,
            &store_id,
            &metadata_hash,
        );

        // Fill Merkle phase rows
        current_row = self.fill_merkle_trace(
            &mut trace,
            current_row,
            &event_tree,
            prev_state_root,
            &new_state_root,
            compliance_accumulator,
            &initial_leaf_level_acc,
            &event_field_acc,
            &leaf_field_acc,
            &batch_id,
            &tenant_id,
            &store_id,
            &metadata_hash,
        );

        // Fill finalization rows
        current_row = self.fill_finalize_trace(
            &mut trace,
            current_row,
            prev_state_root,
            &new_state_root,
            &event_tree,
            compliance_accumulator,
            &event_field_acc,
            &leaf_field_acc,
            &batch_id,
            &tenant_id,
            &store_id,
            &metadata_hash,
        );

        // Fill remaining rows with padding
        self.fill_padding_trace(
            &mut trace,
            current_row,
            prev_state_root,
            &new_state_root,
            &event_tree,
            compliance_accumulator,
            &event_field_acc,
            &leaf_field_acc,
            &batch_id,
            &metadata_hash,
        );

        // Mark last row
        trace[batch_cols::IS_LAST_BATCH_ROW][self.trace_length - 1] = FELT_ONE;

        Ok(TraceTable::init(trace))
    }

    #[allow(clippy::too_many_arguments)]
    fn fill_leaf_trace(
        &self,
        trace: &mut [Vec<Felt>],
        start_row: usize,
        event_leaves: &[EventLeaf],
        event_tree: &EventMerkleTree,
        prev_state_root: &BatchStateRoot,
        new_state_root: &BatchStateRoot,
        compliance_accumulator: Felt,
        event_leaf_acc: &[Felt; 4],
        event_field_acc: &LeafFieldAccumulators,
        batch_id: &[Felt; 4],
        tenant_id: &[Felt; 4],
        store_id: &[Felt; 4],
        metadata_hash: &[Felt; 4],
    ) -> (usize, LeafFieldAccumulators) {
        let padded_leaves = padded_leaf_count(self.witness.num_events());
        let leaf_hashes = event_tree
            .level(0)
            .cloned()
            .unwrap_or_else(|| vec![[FELT_ZERO; 4]; padded_leaves]);

        debug_assert_eq!(leaf_hashes.len(), leaf_row_count(self.witness.num_events()));

        let mut current_row = start_row;
        let mut prev_level_acc = [FELT_ZERO; 4];
        let mut leaf_field_acc = LeafFieldAccumulators::default();
        let gamma = Felt::new(crate::air::trace_layout::MERKLE_LINK_GAMMA);

        for (node_idx, leaf_hash) in leaf_hashes.iter().enumerate() {
            if current_row >= self.trace_length {
                break;
            }

            let leaf = event_leaves.get(node_idx);
            let amount_limbs = self
                .witness
                .events
                .get(node_idx)
                .map(|event| event.amount_limbs());
            let row = current_row;
            trace[batch_cols::BATCH_PHASE][row] = BatchPhase::Leaf.to_felt();
            trace[batch_cols::IS_LEAF_ROW][row] = FELT_ONE;
            trace[batch_cols::IS_LEAF_HASH_ROW][row] = FELT_ZERO;
            trace[batch_cols::IS_COMMITMENT_HASH_ROW][row] = FELT_ZERO;
            trace[batch_cols::IS_MERKLE_ROW][row] = FELT_ZERO;
            trace[batch_cols::IS_FINALIZE_HASH][row] = FELT_ZERO;
            trace[batch_cols::MERKLE_HASH_STEP][row] = FELT_ZERO;
            trace[batch_cols::MERKLE_LEVEL][row] = FELT_ZERO;
            trace[batch_cols::MERKLE_NODE_INDEX][row] = felt_from_u64(node_idx as u64);
            trace[batch_cols::MERKLE_LEVEL_SIZE][row] = felt_from_u64(leaf_hashes.len() as u64);

            for i in 0..4 {
                trace[batch_cols::merkle_output(i)][row] = leaf_hash[i];
                trace[batch_cols::merkle_left(i)][row] = FELT_ZERO;
                trace[batch_cols::merkle_right(i)][row] = event_leaf_acc[i];
                trace[batch_cols::prev_state_root(i)][row] = prev_state_root.root[i];
                trace[batch_cols::new_state_root(i)][row] = new_state_root.root[i];
                trace[batch_cols::event_tree_root(i)][row] = event_tree.root()[i];
                trace[batch_cols::batch_id(i)][row] = batch_id[i];
                trace[batch_cols::metadata_hash(i)][row] = metadata_hash[i];
                trace[batch_cols::TENANT_ID_START + i][row] = tenant_id[i];
                trace[batch_cols::STORE_ID_START + i][row] = store_id[i];
                trace[batch_cols::merkle_prev_level_acc(i)][row] = prev_level_acc[i];
                trace[batch_cols::merkle_consumed_level_acc(i)][row] = FELT_ZERO;
                trace[batch_cols::merkle_curr_level_acc(i)][row] = FELT_ZERO;
                base_cols_fill(trace, row, i, leaf);
            }
            write_event_field_accumulators(trace, row, event_field_acc);
            write_leaf_field_accumulators(trace, row, &leaf_field_acc);
            fill_leaf_amount_columns(trace, row, amount_limbs.as_ref());
            fill_public_inputs_hash_columns(trace, row, leaf);

            trace[batch_cols::COMPLIANCE_ACCUMULATOR][row] = compliance_accumulator;
            trace[batch_cols::EVENT_COMPLIANCE_FLAG][row] =
                leaf.map_or(FELT_ZERO, |leaf| leaf.compliance_flag);
            trace[batch_cols::SEQUENCE_START][row] =
                felt_from_u64(self.witness.metadata.sequence_start);
            trace[batch_cols::SEQUENCE_END][row] =
                felt_from_u64(self.witness.metadata.sequence_end);
            trace[batch_cols::TIMESTAMP][row] = felt_from_u64(self.witness.metadata.timestamp);
            for i in 0..8 {
                trace[batch_cols::POLICY_HASH_START + i][row] = self.witness.policy_hash[i];
            }
            trace[batch_cols::POLICY_LIMIT][row] = felt_from_u64(self.witness.policy_limit);
            trace[batch_cols::NUM_EVENTS][row] = felt_from_u64(self.witness.num_events() as u64);
            trace[batch_cols::EVENT_INDEX][row] = felt_from_u64(self.witness.num_events() as u64);
            trace[batch_cols::EVENT_ROW][row] = FELT_ZERO;
            trace[batch_cols::EVENTS_DONE][row] = FELT_ONE;

            for i in 0..4 {
                prev_level_acc[i] = prev_level_acc[i] * gamma + leaf_hash[i];
            }
            if let (Some(leaf), Some(amount_limbs)) = (leaf, amount_limbs.as_ref()) {
                leaf_field_acc.append_leaf(leaf, amount_limbs, gamma);
            } else {
                leaf_field_acc.append_padding(gamma, &self.witness.policy_hash);
            }

            current_row += 1;
        }

        (current_row, leaf_field_acc)
    }

    /// Build trace rows for a single event
    fn build_event_trace(
        &self,
        event: &BatchEventWitness,
        limit_limbs: &[Felt; 8],
        leaf: &EventLeaf,
    ) -> Result<EventTraceData, BatchError> {
        let amount_limbs = event.amount_limbs();
        let (diff, borrow) = compute_subtraction_witness(&amount_limbs, limit_limbs);
        let junk_bit = felt_from_u64(2);
        let junk_bits = [junk_bit; 32];

        let derived_flag = if borrow[1] == FELT_ZERO {
            FELT_ONE
        } else {
            FELT_ZERO
        };
        if event.compliance_felt() != derived_flag {
            return Err(BatchError::EventNotCompliant {
                event_index: event.event_index,
                message: format!(
                    "Event {} compliance flag mismatch with subtraction witness",
                    event.event_index
                ),
            });
        }

        // Compute bit decomposition
        let limb0_bits = decompose_to_bits(amount_limbs[0]);
        let limb1_bits = decompose_to_bits(amount_limbs[1]);
        let diff0_bits = decompose_to_bits(diff[0]);
        let diff1_bits = decompose_to_bits(diff[1]);
        let leaf_hash = leaf.hash();

        // Build trace rows
        let mut base = vec![vec![FELT_ZERO; ROWS_PER_EVENT]; BASE_TRACE_WIDTH];

        for row in 0..ROWS_PER_EVENT {
            // Rescue state
            for i in 0..4 {
                base[base_cols::RESCUE_STATE_START + i][row] = leaf.amount_commitment[i];
                base[base_cols::RESCUE_STATE_START + 4 + i][row] = leaf.event_id[i];
            }

            let mut row_amount_limbs = amount_limbs;
            let mut row_limit_limbs = *limit_limbs;
            if row != 0 {
                for limb in row_amount_limbs.iter_mut().skip(2) {
                    *limb = junk_bit;
                }
                for limb in row_limit_limbs.iter_mut().skip(2) {
                    *limb = junk_bit;
                }
            }

            // Amount limbs
            for i in 0..8 {
                base[base_cols::AMOUNT_START + i][row] = row_amount_limbs[i];
            }

            // Threshold limbs
            for i in 0..8 {
                base[base_cols::THRESHOLD_START + i][row] = row_limit_limbs[i];
            }

            // Reuse the legacy comparison columns to expose the canonical public-input hash.
            for i in 0..8 {
                base[base_cols::COMPARISON_START + i][row] = leaf.public_inputs_hash[i];
            }

            // Reuse the bit-decomposition columns across the 4-row event segment:
            // - row 0: amount limbs
            // - row 1: subtraction diff limbs
            let (row_bits0, row_bits1) = if row == 0 {
                (limb0_bits, limb1_bits)
            } else if row == 1 {
                (diff0_bits, diff1_bits)
            } else {
                (junk_bits, junk_bits)
            };
            for i in 0..32 {
                base[base_cols::AMOUNT_BITS_LIMB0_START + i][row] = row_bits0[i];
                base[base_cols::AMOUNT_BITS_LIMB1_START + i][row] = row_bits1[i];
            }

            // Control flags (adjusted for batch context)
            base[base_cols::ROUND_COUNTER][row] =
                felt_from_u64((event.event_index * ROWS_PER_EVENT + row) as u64);
            base[base_cols::FLAG_IS_FIRST][row] = if row == 0 && event.event_index == 0 {
                FELT_ONE
            } else {
                FELT_ZERO
            };
            base[base_cols::FLAG_IS_LAST][row] = FELT_ZERO; // Never last in base event trace
        }

        Ok(EventTraceData {
            base,
            diff,
            borrow,
            leaf_hash,
        })
    }

    /// Fill real-event leaf-hash rows (4 Rescue permutations per real leaf).
    #[allow(clippy::too_many_arguments)]
    fn fill_leaf_hash_trace(
        &self,
        trace: &mut [Vec<Felt>],
        start_row: usize,
        event_leaves: &[EventLeaf],
        prev_state_root: &BatchStateRoot,
        new_state_root: &BatchStateRoot,
        event_tree: &EventMerkleTree,
        compliance_accumulator: Felt,
        leaf_level_acc: &[Felt; 4],
        event_field_acc: &LeafFieldAccumulators,
        leaf_field_acc: &LeafFieldAccumulators,
        batch_id: &[Felt; 4],
        tenant_id: &[Felt; 4],
        store_id: &[Felt; 4],
        metadata_hash: &[Felt; 4],
    ) -> usize {
        debug_assert_eq!(
            leaf_hash_row_count(self.witness.num_events()),
            self.witness.num_events() * ROWS_PER_LEAF_HASH
        );

        let mut current_row = start_row;
        let mut derived_leaf_acc = [FELT_ZERO; 4];
        let gamma = Felt::new(crate::air::trace_layout::MERKLE_LINK_GAMMA);
        let padded_leaves = padded_leaf_count(self.witness.num_events());

        for (event_idx, leaf) in event_leaves.iter().enumerate() {
            if current_row >= self.trace_length {
                break;
            }

            let amount_limbs = self.witness.events[event_idx].amount_limbs();
            let leaf_hash = leaf.hash();

            let mut chunk0_state = [FELT_ZERO; RESCUE_STATE_WIDTH];
            chunk0_state[..4].copy_from_slice(&leaf.event_id);
            chunk0_state[4..8].copy_from_slice(&leaf.amount_commitment);
            chunk0_state[8] = felt_from_u64(25);
            let chunk0_trace = rescue_permutation_trace(&chunk0_state);

            let mut chunk1_state = chunk0_trace[ROWS_PER_MERKLE_NODE - 1];
            for i in 0..4 {
                chunk1_state[i] += leaf.policy_hash[i];
                chunk1_state[4 + i] += leaf.policy_hash[4 + i];
            }
            let chunk1_trace = rescue_permutation_trace(&chunk1_state);

            let mut chunk2_state = chunk1_trace[ROWS_PER_MERKLE_NODE - 1];
            for i in 0..4 {
                chunk2_state[i] += leaf.public_inputs_hash[i];
                chunk2_state[4 + i] += leaf.public_inputs_hash[4 + i];
            }
            let chunk2_trace = rescue_permutation_trace(&chunk2_state);

            let mut chunk3_state = chunk2_trace[ROWS_PER_MERKLE_NODE - 1];
            chunk3_state[0] += leaf.compliance_flag;
            let chunk3_trace = rescue_permutation_trace(&chunk3_state);

            let chunk_traces = [chunk0_trace, chunk1_trace, chunk2_trace, chunk3_trace];

            for (chunk_idx, trace_rows) in chunk_traces.iter().enumerate() {
                for (step, trace_row) in trace_rows.iter().enumerate() {
                    let row = current_row + chunk_idx * ROWS_PER_MERKLE_NODE + step;
                    if row >= self.trace_length {
                        break;
                    }

                    for (i, lane) in trace_row.iter().enumerate() {
                        trace[batch_cols::merkle_rescue_state(i)][row] = *lane;
                    }
                    trace[batch_cols::MERKLE_HASH_STEP][row] = felt_from_u64(step as u64);
                    trace[batch_cols::IS_FINALIZE_HASH][row] = FELT_ZERO;
                    trace[batch_cols::IS_LEAF_ROW][row] = FELT_ZERO;
                    trace[batch_cols::IS_LEAF_HASH_ROW][row] = FELT_ONE;
                    trace[batch_cols::IS_COMMITMENT_HASH_ROW][row] = FELT_ZERO;
                    trace[batch_cols::IS_MERKLE_ROW][row] = FELT_ZERO;
                    trace[batch_cols::BATCH_PHASE][row] = BatchPhase::LeafHash.to_felt();
                    trace[batch_cols::MERKLE_LEVEL][row] = felt_from_u64(chunk_idx as u64);
                    trace[batch_cols::MERKLE_NODE_INDEX][row] = felt_from_u64(event_idx as u64);
                    trace[batch_cols::MERKLE_LEVEL_SIZE][row] = felt_from_u64(padded_leaves as u64);

                    match chunk_idx {
                        0 => {
                            for i in 0..4 {
                                trace[batch_cols::merkle_left(i)][row] = leaf.event_id[i];
                                trace[batch_cols::merkle_right(i)][row] = leaf.amount_commitment[i];
                            }
                        }
                        1 => {
                            for i in 0..4 {
                                trace[batch_cols::merkle_left(i)][row] = leaf.policy_hash[i];
                                trace[batch_cols::merkle_right(i)][row] = leaf.policy_hash[4 + i];
                            }
                        }
                        2 => {
                            for i in 0..4 {
                                trace[batch_cols::merkle_left(i)][row] = leaf.public_inputs_hash[i];
                                trace[batch_cols::merkle_right(i)][row] =
                                    leaf.public_inputs_hash[4 + i];
                            }
                        }
                        _ => {
                            trace[batch_cols::merkle_left(0)][row] = leaf.compliance_flag;
                            for i in 1..4 {
                                trace[batch_cols::merkle_left(i)][row] = FELT_ZERO;
                            }
                            for i in 0..4 {
                                trace[batch_cols::merkle_right(i)][row] = FELT_ZERO;
                            }
                        }
                    }

                    for i in 0..4 {
                        trace[batch_cols::merkle_output(i)][row] = leaf_hash[i];
                        trace[batch_cols::prev_state_root(i)][row] = prev_state_root.root[i];
                        trace[batch_cols::new_state_root(i)][row] = new_state_root.root[i];
                        trace[batch_cols::event_tree_root(i)][row] = event_tree.root()[i];
                        trace[batch_cols::batch_id(i)][row] = batch_id[i];
                        trace[batch_cols::metadata_hash(i)][row] = metadata_hash[i];
                        trace[batch_cols::TENANT_ID_START + i][row] = tenant_id[i];
                        trace[batch_cols::STORE_ID_START + i][row] = store_id[i];
                        trace[batch_cols::merkle_prev_level_acc(i)][row] = leaf_level_acc[i];
                        trace[batch_cols::merkle_curr_level_acc(i)][row] = derived_leaf_acc[i];
                        trace[batch_cols::merkle_consumed_level_acc(i)][row] = FELT_ZERO;
                        base_cols_fill(trace, row, i, Some(leaf));
                    }
                    write_event_field_accumulators(trace, row, event_field_acc);
                    write_leaf_field_accumulators(trace, row, leaf_field_acc);
                    fill_leaf_amount_columns(trace, row, Some(&amount_limbs));
                    fill_public_inputs_hash_columns(trace, row, Some(leaf));

                    trace[batch_cols::COMPLIANCE_ACCUMULATOR][row] = compliance_accumulator;
                    trace[batch_cols::EVENT_COMPLIANCE_FLAG][row] = leaf.compliance_flag;
                    trace[batch_cols::SEQUENCE_START][row] =
                        felt_from_u64(self.witness.metadata.sequence_start);
                    trace[batch_cols::SEQUENCE_END][row] =
                        felt_from_u64(self.witness.metadata.sequence_end);
                    trace[batch_cols::TIMESTAMP][row] =
                        felt_from_u64(self.witness.metadata.timestamp);
                    for i in 0..8 {
                        trace[batch_cols::POLICY_HASH_START + i][row] = self.witness.policy_hash[i];
                    }
                    trace[batch_cols::POLICY_LIMIT][row] = felt_from_u64(self.witness.policy_limit);
                    trace[batch_cols::NUM_EVENTS][row] =
                        felt_from_u64(self.witness.num_events() as u64);
                    trace[batch_cols::EVENT_INDEX][row] =
                        felt_from_u64(self.witness.num_events() as u64);
                    trace[batch_cols::EVENT_ROW][row] = FELT_ZERO;
                    trace[batch_cols::EVENTS_DONE][row] = FELT_ONE;
                }
            }

            for i in 0..4 {
                derived_leaf_acc[i] = derived_leaf_acc[i] * gamma + leaf_hash[i];
            }
            current_row += ROWS_PER_LEAF_HASH;
        }

        current_row
    }

    /// Fill real-event amount-commitment hash rows (ROWS_PER_COMMITMENT_HASH rows per event).
    #[allow(clippy::too_many_arguments)]
    fn fill_commitment_hash_trace(
        &self,
        trace: &mut [Vec<Felt>],
        start_row: usize,
        prev_state_root: &BatchStateRoot,
        new_state_root: &BatchStateRoot,
        event_tree: &EventMerkleTree,
        compliance_accumulator: Felt,
        leaf_level_acc: &[Felt; 4],
        event_field_acc: &LeafFieldAccumulators,
        leaf_field_acc: &LeafFieldAccumulators,
        batch_id: &[Felt; 4],
        tenant_id: &[Felt; 4],
        store_id: &[Felt; 4],
        metadata_hash: &[Felt; 4],
    ) -> usize {
        let mut current_row = start_row;
        let gamma = Felt::new(crate::air::trace_layout::MERKLE_LINK_GAMMA);
        let padded_leaves = padded_leaf_count(self.witness.num_events());
        let mut commitment_acc = [FELT_ZERO; 4];
        let mut amount_acc = [FELT_ZERO; 2];

        for (event_idx, event) in self.witness.events.iter().enumerate() {
            if current_row >= self.trace_length {
                break;
            }

            let amount_limbs = event.amount_limbs();
            let commitment = event.amount_commitment();

            let mut hash_state = [FELT_ZERO; RESCUE_STATE_WIDTH];
            hash_state[..8].copy_from_slice(&amount_limbs);
            let trace_rows = rescue_permutation_trace(&hash_state);

            for (step, trace_row) in trace_rows.iter().enumerate().take(ROWS_PER_COMMITMENT_HASH) {
                let row = current_row + step;
                if row >= self.trace_length {
                    break;
                }

                for (i, lane) in trace_row.iter().enumerate() {
                    trace[batch_cols::merkle_rescue_state(i)][row] = *lane;
                }
                trace[batch_cols::MERKLE_HASH_STEP][row] = felt_from_u64(step as u64);
                trace[batch_cols::IS_FINALIZE_HASH][row] = FELT_ZERO;
                trace[batch_cols::IS_LEAF_ROW][row] = FELT_ZERO;
                trace[batch_cols::IS_LEAF_HASH_ROW][row] = FELT_ZERO;
                trace[batch_cols::IS_COMMITMENT_HASH_ROW][row] = FELT_ONE;
                trace[batch_cols::IS_MERKLE_ROW][row] = FELT_ZERO;
                trace[batch_cols::BATCH_PHASE][row] = BatchPhase::CommitmentHash.to_felt();
                trace[batch_cols::MERKLE_LEVEL][row] = FELT_ZERO;
                trace[batch_cols::MERKLE_NODE_INDEX][row] = felt_from_u64(event_idx as u64);
                trace[batch_cols::MERKLE_LEVEL_SIZE][row] = felt_from_u64(padded_leaves as u64);

                for i in 0..4 {
                    trace[batch_cols::merkle_left(i)][row] = amount_limbs[i];
                    trace[batch_cols::merkle_right(i)][row] = amount_limbs[4 + i];
                    trace[batch_cols::merkle_output(i)][row] = commitment[i];
                    trace[batch_cols::prev_state_root(i)][row] = prev_state_root.root[i];
                    trace[batch_cols::new_state_root(i)][row] = new_state_root.root[i];
                    trace[batch_cols::event_tree_root(i)][row] = event_tree.root()[i];
                    trace[batch_cols::batch_id(i)][row] = batch_id[i];
                    trace[batch_cols::metadata_hash(i)][row] = metadata_hash[i];
                    trace[batch_cols::TENANT_ID_START + i][row] = tenant_id[i];
                    trace[batch_cols::STORE_ID_START + i][row] = store_id[i];
                    trace[batch_cols::merkle_prev_level_acc(i)][row] = leaf_level_acc[i];
                    trace[batch_cols::merkle_curr_level_acc(i)][row] = commitment_acc[i];
                }
                trace[batch_cols::merkle_consumed_level_acc(0)][row] = amount_acc[0];
                trace[batch_cols::merkle_consumed_level_acc(1)][row] = amount_acc[1];
                trace[batch_cols::merkle_consumed_level_acc(2)][row] = FELT_ZERO;
                trace[batch_cols::merkle_consumed_level_acc(3)][row] = FELT_ZERO;
                write_event_field_accumulators(trace, row, event_field_acc);
                write_leaf_field_accumulators(trace, row, leaf_field_acc);
                fill_leaf_amount_columns(trace, row, Some(&amount_limbs));

                trace[batch_cols::COMPLIANCE_ACCUMULATOR][row] = compliance_accumulator;
                trace[batch_cols::EVENT_COMPLIANCE_FLAG][row] = filler_bit(row as u64);
                trace[batch_cols::SEQUENCE_START][row] =
                    felt_from_u64(self.witness.metadata.sequence_start);
                trace[batch_cols::SEQUENCE_END][row] =
                    felt_from_u64(self.witness.metadata.sequence_end);
                trace[batch_cols::TIMESTAMP][row] = felt_from_u64(self.witness.metadata.timestamp);
                for i in 0..8 {
                    trace[batch_cols::POLICY_HASH_START + i][row] = self.witness.policy_hash[i];
                }
                trace[batch_cols::POLICY_LIMIT][row] = felt_from_u64(self.witness.policy_limit);
                trace[batch_cols::NUM_EVENTS][row] =
                    felt_from_u64(self.witness.num_events() as u64);
                trace[batch_cols::EVENT_INDEX][row] =
                    felt_from_u64(self.witness.num_events() as u64);
                trace[batch_cols::EVENT_ROW][row] = FELT_ZERO;
                trace[batch_cols::EVENTS_DONE][row] = FELT_ONE;
            }

            for i in 0..4 {
                commitment_acc[i] = commitment_acc[i] * gamma + commitment[i];
            }
            for (i, tag) in AMOUNT_STREAM_LANE_TAGS.iter().enumerate() {
                amount_acc[i] = amount_acc[i] * gamma + amount_limbs[i] + felt_from_u64(*tag);
            }
            current_row += ROWS_PER_COMMITMENT_HASH;
        }

        current_row
    }

    /// Fill Merkle tree computation rows (ROWS_PER_MERKLE_NODE rows per node).
    ///
    /// For each internal node, we emit in-circuit Rescue states:
    /// - steps 0..13: half-round transitions
    /// - step 14: output state row
    #[allow(clippy::too_many_arguments)]
    fn fill_merkle_trace(
        &self,
        trace: &mut [Vec<Felt>],
        start_row: usize,
        event_tree: &EventMerkleTree,
        prev_state_root: &BatchStateRoot,
        new_state_root: &BatchStateRoot,
        compliance_accumulator: Felt,
        initial_prev_level_acc: &[Felt; 4],
        event_field_acc: &LeafFieldAccumulators,
        leaf_field_acc: &LeafFieldAccumulators,
        batch_id: &[Felt; 4],
        tenant_id: &[Felt; 4],
        store_id: &[Felt; 4],
        metadata_hash: &[Felt; 4],
    ) -> usize {
        let levels = event_tree.levels();
        let mut current_row = start_row;
        let gamma = Felt::new(crate::air::trace_layout::MERKLE_LINK_GAMMA);
        let mut prev_level_acc = *initial_prev_level_acc;

        for (level_offset, level) in levels.iter().enumerate() {
            let level_idx = level_offset + 1;
            let mut consumed_level_acc = [FELT_ZERO; 4];
            let mut curr_level_acc = [FELT_ZERO; 4];

            for (node_idx, node) in level.iter().enumerate() {
                if current_row >= self.trace_length {
                    return current_row;
                }

                let (left_child, right_child) =
                    if let Some(children) = event_tree.level(level_idx - 1) {
                        (
                            children
                                .get(node_idx * 2)
                                .copied()
                                .unwrap_or([FELT_ZERO; 4]),
                            children
                                .get(node_idx * 2 + 1)
                                .copied()
                                .unwrap_or([FELT_ZERO; 4]),
                        )
                    } else {
                        ([FELT_ZERO; 4], [FELT_ZERO; 4])
                    };

                let mut hash_state = [FELT_ZERO; 12];
                hash_state[..4].copy_from_slice(&left_child);
                hash_state[4..8].copy_from_slice(&right_child);
                let trace_rows = rescue_permutation_trace(&hash_state);

                for (step, trace_row) in trace_rows.iter().enumerate() {
                    let row = current_row + step;
                    if row >= self.trace_length {
                        break;
                    }

                    for (i, lane) in trace_row.iter().enumerate() {
                        trace[batch_cols::merkle_rescue_state(i)][row] = *lane;
                    }
                    trace[batch_cols::MERKLE_HASH_STEP][row] = felt_from_u64(step as u64);
                    trace[batch_cols::IS_FINALIZE_HASH][row] = FELT_ZERO;
                    trace[batch_cols::IS_LEAF_ROW][row] = FELT_ZERO;
                    trace[batch_cols::IS_LEAF_HASH_ROW][row] = FELT_ZERO;
                    trace[batch_cols::IS_COMMITMENT_HASH_ROW][row] = FELT_ZERO;
                    trace[batch_cols::IS_MERKLE_ROW][row] = FELT_ONE;
                    trace[batch_cols::BATCH_PHASE][row] = BatchPhase::Merkle.to_felt();

                    trace[batch_cols::MERKLE_LEVEL][row] = felt_from_u64(level_idx as u64);
                    trace[batch_cols::MERKLE_NODE_INDEX][row] = felt_from_u64(node_idx as u64);
                    trace[batch_cols::MERKLE_LEVEL_SIZE][row] = felt_from_u64(level.len() as u64);

                    for i in 0..4 {
                        trace[batch_cols::merkle_output(i)][row] = node[i];
                        trace[batch_cols::merkle_left(i)][row] = left_child[i];
                        trace[batch_cols::merkle_right(i)][row] = right_child[i];
                    }

                    for i in 0..4 {
                        trace[batch_cols::prev_state_root(i)][row] = prev_state_root.root[i];
                        trace[batch_cols::new_state_root(i)][row] = new_state_root.root[i];
                        trace[batch_cols::event_tree_root(i)][row] = event_tree.root()[i];
                        trace[batch_cols::merkle_prev_level_acc(i)][row] = prev_level_acc[i];
                        trace[batch_cols::merkle_consumed_level_acc(i)][row] =
                            consumed_level_acc[i];
                        trace[batch_cols::merkle_curr_level_acc(i)][row] = curr_level_acc[i];
                    }
                    write_event_field_accumulators(trace, row, event_field_acc);
                    write_leaf_field_accumulators(trace, row, leaf_field_acc);

                    trace[batch_cols::COMPLIANCE_ACCUMULATOR][row] = compliance_accumulator;
                    trace[batch_cols::EVENT_COMPLIANCE_FLAG][row] = filler_bit(row as u64);

                    for i in 0..4 {
                        trace[batch_cols::batch_id(i)][row] = batch_id[i];
                        trace[batch_cols::metadata_hash(i)][row] = metadata_hash[i];
                        trace[batch_cols::TENANT_ID_START + i][row] = tenant_id[i];
                        trace[batch_cols::STORE_ID_START + i][row] = store_id[i];
                    }
                    trace[batch_cols::SEQUENCE_START][row] =
                        felt_from_u64(self.witness.metadata.sequence_start);
                    trace[batch_cols::SEQUENCE_END][row] =
                        felt_from_u64(self.witness.metadata.sequence_end);
                    trace[batch_cols::TIMESTAMP][row] =
                        felt_from_u64(self.witness.metadata.timestamp);

                    for i in 0..8 {
                        trace[batch_cols::POLICY_HASH_START + i][row] = self.witness.policy_hash[i];
                    }
                    trace[batch_cols::POLICY_LIMIT][row] = felt_from_u64(self.witness.policy_limit);

                    trace[batch_cols::NUM_EVENTS][row] =
                        felt_from_u64(self.witness.num_events() as u64);
                    trace[batch_cols::EVENT_INDEX][row] =
                        felt_from_u64(self.witness.num_events() as u64);
                    trace[batch_cols::EVENT_ROW][row] = FELT_ZERO;
                    trace[batch_cols::EVENTS_DONE][row] = FELT_ONE;

                    if step == 0 {
                        for i in 0..4 {
                            consumed_level_acc[i] = (consumed_level_acc[i] * gamma + left_child[i])
                                * gamma
                                + right_child[i];
                        }
                    }
                    if step == ROWS_PER_MERKLE_NODE - 1 {
                        for i in 0..4 {
                            curr_level_acc[i] = curr_level_acc[i] * gamma + node[i];
                        }
                    }
                }

                current_row += ROWS_PER_MERKLE_NODE;
            }

            if level_idx < levels.len() {
                prev_level_acc = curr_level_acc;
            }
        }

        current_row
    }

    /// Fill finalization rows (ROWS_PER_MERKLE_NODE rows).
    ///
    /// The finalization phase represents:
    ///   new_state_root = Rescue(event_tree_root || metadata_hash || prev_state_root)
    /// where `metadata_hash = Rescue(prev_state_root || batch_metadata)`.
    #[allow(clippy::too_many_arguments)]
    fn fill_finalize_trace(
        &self,
        trace: &mut [Vec<Felt>],
        start_row: usize,
        prev_state_root: &BatchStateRoot,
        new_state_root: &BatchStateRoot,
        event_tree: &EventMerkleTree,
        compliance_accumulator: Felt,
        event_field_acc: &LeafFieldAccumulators,
        leaf_field_acc: &LeafFieldAccumulators,
        batch_id: &[Felt; 4],
        tenant_id: &[Felt; 4],
        store_id: &[Felt; 4],
        metadata_hash: &[Felt; 4],
    ) -> usize {
        let mut current_row = start_row;
        let finalize_prev_level_acc = if event_tree.depth() == 0 {
            event_tree.root()
        } else {
            [FELT_ZERO; 4]
        };

        let event_tree_root = event_tree.root();
        let mut hash_state = [FELT_ZERO; RESCUE_STATE_WIDTH];
        hash_state[..4].copy_from_slice(&event_tree_root);
        hash_state[4..8].copy_from_slice(metadata_hash);
        hash_state[8..12].copy_from_slice(&prev_state_root.root);
        let trace_rows = rescue_permutation_trace(&hash_state);

        for (step, trace_row) in trace_rows.iter().enumerate().take(FINALIZE_ROWS) {
            let row = current_row;
            if row >= self.trace_length {
                break;
            }

            for (i, lane) in trace_row.iter().enumerate() {
                trace[batch_cols::merkle_rescue_state(i)][row] = *lane;
            }
            for i in 0..4 {
                trace[batch_cols::merkle_output(i)][row] = new_state_root.root[i];
            }

            trace[batch_cols::MERKLE_HASH_STEP][row] = felt_from_u64(step as u64);
            trace[batch_cols::IS_FINALIZE_HASH][row] = FELT_ONE;
            trace[batch_cols::IS_LEAF_ROW][row] = FELT_ZERO;
            trace[batch_cols::IS_LEAF_HASH_ROW][row] = FELT_ZERO;
            trace[batch_cols::IS_COMMITMENT_HASH_ROW][row] = FELT_ZERO;
            trace[batch_cols::IS_MERKLE_ROW][row] = FELT_ZERO;
            trace[batch_cols::BATCH_PHASE][row] = BatchPhase::Finalize.to_felt();
            trace[batch_cols::MERKLE_LEVEL][row] = FELT_ZERO;
            trace[batch_cols::MERKLE_NODE_INDEX][row] = FELT_ZERO;
            trace[batch_cols::MERKLE_LEVEL_SIZE][row] = FELT_ZERO;

            for i in 0..4 {
                trace[batch_cols::prev_state_root(i)][row] = prev_state_root.root[i];
                trace[batch_cols::new_state_root(i)][row] = new_state_root.root[i];
                trace[batch_cols::event_tree_root(i)][row] = event_tree.root()[i];
            }
            write_event_field_accumulators(trace, row, event_field_acc);
            write_leaf_field_accumulators(trace, row, leaf_field_acc);

            trace[batch_cols::COMPLIANCE_ACCUMULATOR][row] = compliance_accumulator;
            trace[batch_cols::EVENT_COMPLIANCE_FLAG][row] = filler_bit(row as u64);

            for i in 0..4 {
                trace[batch_cols::batch_id(i)][row] = batch_id[i];
                trace[batch_cols::metadata_hash(i)][row] = metadata_hash[i];
                trace[batch_cols::TENANT_ID_START + i][row] = tenant_id[i];
                trace[batch_cols::STORE_ID_START + i][row] = store_id[i];
            }
            trace[batch_cols::SEQUENCE_START][row] =
                felt_from_u64(self.witness.metadata.sequence_start);
            trace[batch_cols::SEQUENCE_END][row] =
                felt_from_u64(self.witness.metadata.sequence_end);
            trace[batch_cols::TIMESTAMP][row] = felt_from_u64(self.witness.metadata.timestamp);

            for i in 0..8 {
                trace[batch_cols::POLICY_HASH_START + i][row] = self.witness.policy_hash[i];
            }
            trace[batch_cols::POLICY_LIMIT][row] = felt_from_u64(self.witness.policy_limit);
            trace[batch_cols::NUM_EVENTS][row] = felt_from_u64(self.witness.num_events() as u64);
            trace[batch_cols::EVENT_INDEX][row] = felt_from_u64(self.witness.num_events() as u64);
            trace[batch_cols::EVENT_ROW][row] = FELT_ZERO;
            trace[batch_cols::EVENTS_DONE][row] = FELT_ONE;
            for i in 0..4 {
                trace[batch_cols::merkle_prev_level_acc(i)][row] = finalize_prev_level_acc[i];
                trace[batch_cols::merkle_consumed_level_acc(i)][row] = FELT_ZERO;
                trace[batch_cols::merkle_curr_level_acc(i)][row] = FELT_ZERO;
            }

            current_row += 1;
        }

        current_row
    }

    /// Fill padding rows
    #[allow(clippy::too_many_arguments)]
    fn fill_padding_trace(
        &self,
        trace: &mut [Vec<Felt>],
        start_row: usize,
        prev_state_root: &BatchStateRoot,
        new_state_root: &BatchStateRoot,
        event_tree: &EventMerkleTree,
        compliance_accumulator: Felt,
        event_field_acc: &LeafFieldAccumulators,
        leaf_field_acc: &LeafFieldAccumulators,
        batch_id: &[Felt; 4],
        metadata_hash: &[Felt; 4],
    ) {
        let tenant_id = self.witness.tenant_id_felts();
        let store_id = self.witness.store_id_felts();

        for row in start_row..self.trace_length {
            trace[batch_cols::BATCH_PHASE][row] = BatchPhase::Padding.to_felt();
            trace[batch_cols::IS_LEAF_ROW][row] = FELT_ZERO;
            trace[batch_cols::IS_LEAF_HASH_ROW][row] = FELT_ZERO;
            trace[batch_cols::IS_COMMITMENT_HASH_ROW][row] = FELT_ZERO;
            trace[batch_cols::IS_MERKLE_ROW][row] = FELT_ZERO;
            trace[batch_cols::IS_FINALIZE_HASH][row] = FELT_ZERO;
            trace[batch_cols::MERKLE_HASH_STEP][row] = FELT_ZERO;
            trace[batch_cols::MERKLE_LEVEL][row] = FELT_ZERO;
            trace[batch_cols::MERKLE_NODE_INDEX][row] = FELT_ZERO;
            trace[batch_cols::MERKLE_LEVEL_SIZE][row] = FELT_ZERO;

            // State roots (constant)
            for i in 0..4 {
                trace[batch_cols::prev_state_root(i)][row] = prev_state_root.root[i];
                trace[batch_cols::new_state_root(i)][row] = new_state_root.root[i];
                trace[batch_cols::event_tree_root(i)][row] = event_tree.root()[i];
            }
            write_event_field_accumulators(trace, row, event_field_acc);
            write_leaf_field_accumulators(trace, row, leaf_field_acc);

            // Compliance (constant)
            trace[batch_cols::COMPLIANCE_ACCUMULATOR][row] = compliance_accumulator;
            trace[batch_cols::EVENT_COMPLIANCE_FLAG][row] = filler_bit(row as u64);

            // Metadata (constant)
            for i in 0..4 {
                trace[batch_cols::batch_id(i)][row] = batch_id[i];
                trace[batch_cols::metadata_hash(i)][row] = metadata_hash[i];
            }

            for i in 0..4 {
                trace[batch_cols::TENANT_ID_START + i][row] = tenant_id[i];
                trace[batch_cols::STORE_ID_START + i][row] = store_id[i];
            }
            trace[batch_cols::SEQUENCE_START][row] =
                felt_from_u64(self.witness.metadata.sequence_start);
            trace[batch_cols::SEQUENCE_END][row] =
                felt_from_u64(self.witness.metadata.sequence_end);
            trace[batch_cols::TIMESTAMP][row] = felt_from_u64(self.witness.metadata.timestamp);

            // Policy (constant)
            for i in 0..8 {
                trace[batch_cols::POLICY_HASH_START + i][row] = self.witness.policy_hash[i];
            }
            trace[batch_cols::POLICY_LIMIT][row] = felt_from_u64(self.witness.policy_limit);

            // Event info
            trace[batch_cols::NUM_EVENTS][row] = felt_from_u64(self.witness.num_events() as u64);
            trace[batch_cols::EVENT_INDEX][row] = felt_from_u64(self.witness.num_events() as u64);
            trace[batch_cols::EVENTS_DONE][row] = FELT_ONE;
            trace[batch_cols::EVENT_ROW][row] = FELT_ZERO;
            for i in 0..4 {
                trace[batch_cols::merkle_prev_level_acc(i)][row] = FELT_ZERO;
                trace[batch_cols::merkle_consumed_level_acc(i)][row] = FELT_ZERO;
                trace[batch_cols::merkle_curr_level_acc(i)][row] = FELT_ZERO;
            }
        }
    }

    /// Get the trace length
    pub fn trace_length(&self) -> usize {
        self.trace_length
    }
}

/// Trace data for a single event
struct EventTraceData {
    /// Base compliance trace columns [col][row]
    base: Vec<Vec<Felt>>,
    /// 2-limb subtraction diff witness.
    diff: [Felt; 2],
    /// 2-limb subtraction borrow witness.
    borrow: [Felt; 2],
    /// Merkle leaf hash claimed by this event segment.
    leaf_hash: [Felt; 4],
}

fn base_cols_fill(trace: &mut [Vec<Felt>], row: usize, i: usize, leaf: Option<&EventLeaf>) {
    trace[base_cols::RESCUE_STATE_START + i][row] =
        leaf.map_or(FELT_ZERO, |leaf| leaf.amount_commitment[i]);
    trace[base_cols::RESCUE_STATE_START + 4 + i][row] =
        leaf.map_or(FELT_ZERO, |leaf| leaf.event_id[i]);
}

fn write_event_field_accumulators(
    trace: &mut [Vec<Felt>],
    row: usize,
    acc: &LeafFieldAccumulators,
) {
    for i in 0..4 {
        trace[batch_cols::event_commitment_acc(i)][row] = acc.commitment[i];
        trace[batch_cols::event_id_acc(i)][row] = acc.event_id[i];
    }
    for i in 0..8 {
        trace[batch_cols::event_policy_acc(i)][row] = acc.policy_hash[i];
        trace[batch_cols::event_public_inputs_acc(i)][row] = acc.public_inputs_hash[i];
    }
    for i in 0..2 {
        trace[batch_cols::event_amount_acc(i)][row] = acc.amount[i];
    }
    trace[batch_cols::EVENT_FLAG_ACC][row] = acc.flag;
}

fn write_leaf_field_accumulators(trace: &mut [Vec<Felt>], row: usize, acc: &LeafFieldAccumulators) {
    for i in 0..4 {
        trace[batch_cols::leaf_commitment_acc(i)][row] = acc.commitment[i];
        trace[batch_cols::leaf_id_acc(i)][row] = acc.event_id[i];
    }
    for i in 0..8 {
        trace[batch_cols::leaf_policy_acc(i)][row] = acc.policy_hash[i];
        trace[batch_cols::leaf_public_inputs_acc(i)][row] = acc.public_inputs_hash[i];
    }
    for i in 0..2 {
        trace[batch_cols::leaf_amount_acc(i)][row] = acc.amount[i];
    }
    trace[batch_cols::LEAF_FLAG_ACC][row] = acc.flag;
}

fn fill_leaf_amount_columns(trace: &mut [Vec<Felt>], row: usize, amount_limbs: Option<&[Felt; 8]>) {
    if let Some(amount_limbs) = amount_limbs {
        for (i, limb) in amount_limbs.iter().enumerate() {
            trace[base_cols::AMOUNT_START + i][row] = *limb;
        }
    }
}

fn fill_public_inputs_hash_columns(trace: &mut [Vec<Felt>], row: usize, leaf: Option<&EventLeaf>) {
    for i in 0..8 {
        trace[base_cols::COMPARISON_START + i][row] =
            leaf.map_or(FELT_ZERO, |leaf| leaf.public_inputs_hash[i]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air::trace_layout::{commitment_hash_row_count, merkle_row_count};
    use crate::prover::witness::BatchWitnessBuilder;
    use crate::state::{BatchMetadata, BatchStateRoot};
    use uuid::Uuid;
    use ves_stark_primitives::public_inputs::{
        compute_policy_hash, witness_commitment_u64_to_hex, CompliancePublicInputs, PolicyParams,
    };
    use ves_stark_primitives::rescue::rescue_hash;
    use winter_prover::Trace;

    fn sample_public_inputs_with_policy(
        policy_id: &str,
        params: PolicyParams,
        amount: u64,
        idx: usize,
        tenant_id: Uuid,
        store_id: Uuid,
    ) -> CompliancePublicInputs {
        let hash = compute_policy_hash(policy_id, &params).unwrap();
        let mut amount_limbs = [FELT_ZERO; 8];
        amount_limbs[0] = felt_from_u64(amount & 0xFFFFFFFF);
        amount_limbs[1] = felt_from_u64(amount >> 32);
        let commitment = rescue_hash(&amount_limbs);
        let commitment_u64 = [
            commitment[0].as_int(),
            commitment[1].as_int(),
            commitment[2].as_int(),
            commitment[3].as_int(),
        ];

        CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id,
            store_id,
            sequence_number: idx as u64,
            payload_kind: 1,
            payload_plain_hash: "0".repeat(64),
            payload_cipher_hash: "0".repeat(64),
            event_signing_hash: "0".repeat(64),
            policy_id: policy_id.to_string(),
            policy_params: params,
            policy_hash: hash.to_hex(),
            witness_commitment: Some(witness_commitment_u64_to_hex(&commitment_u64)),
            authorization_receipt_hash: None,
        }
    }

    fn sample_public_inputs(
        threshold: u64,
        amount: u64,
        idx: usize,
        tenant_id: Uuid,
        store_id: Uuid,
    ) -> CompliancePublicInputs {
        sample_public_inputs_with_policy(
            "aml.threshold",
            PolicyParams::threshold(threshold),
            amount,
            idx,
            tenant_id,
            store_id,
        )
    }

    fn sample_policy_hash(threshold: u64) -> [Felt; 8] {
        let policy_id = "aml.threshold";
        let params = PolicyParams::threshold(threshold);
        let hash = compute_policy_hash(policy_id, &params).unwrap();
        ves_stark_primitives::hash_to_felts(&hash)
    }

    fn sample_policy_hash_with_id(policy_id: &str, params: PolicyParams) -> [Felt; 8] {
        let hash = compute_policy_hash(policy_id, &params).unwrap();
        ves_stark_primitives::hash_to_felts(&hash)
    }

    #[test]
    fn test_batch_trace_builder_small() {
        let threshold = 10000u64;
        let policy_hash = sample_policy_hash(threshold);
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();
        let metadata = BatchMetadata::with_ids(Uuid::new_v4(), tenant_id, store_id, 0, 7);

        let mut builder = BatchWitnessBuilder::new()
            .metadata(metadata)
            .policy_hash(policy_hash)
            .policy_limit(threshold);

        // Add 8 compliant events
        for i in 0..8 {
            let amount = 5000 + i as u64 * 100;
            let inputs = sample_public_inputs(threshold, amount, i, tenant_id, store_id);
            builder = builder.add_event(amount, inputs).unwrap();
        }

        let witness = builder.build().unwrap();
        let trace_builder = BatchTraceBuilder::new(witness);
        let trace = trace_builder.build().unwrap();

        assert_eq!(trace.width(), BATCH_TRACE_WIDTH);
        assert!(trace.length() >= crate::air::trace_layout::MIN_BATCH_TRACE_LENGTH);
    }

    #[test]
    fn test_batch_trace_state_roots() {
        let threshold = 10000u64;
        let policy_hash = sample_policy_hash(threshold);
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();
        let metadata = BatchMetadata::with_ids(Uuid::new_v4(), tenant_id, store_id, 0, 3);

        let mut builder = BatchWitnessBuilder::new()
            .metadata(metadata)
            .policy_hash(policy_hash)
            .policy_limit(threshold);

        for i in 0..4 {
            let amount = 5000;
            let inputs = sample_public_inputs(threshold, amount, i, tenant_id, store_id);
            builder = builder.add_event(5000, inputs).unwrap();
        }

        let witness = builder.build().unwrap();
        let new_root = witness.compute_new_state_root().unwrap();

        let trace_builder = BatchTraceBuilder::new(witness);
        let trace = trace_builder.build().unwrap();

        // Check state root at first row
        for i in 0..4 {
            let trace_root = trace.get(batch_cols::new_state_root(i), 0);
            assert_eq!(trace_root, new_root.root[i]);
        }

        // Check state root at last row
        for i in 0..4 {
            let trace_root = trace.get(batch_cols::new_state_root(i), trace.length() - 1);
            assert_eq!(trace_root, new_root.root[i]);
        }
    }

    #[test]
    fn test_batch_trace_compliance_accumulator() {
        let threshold = 10000u64;
        let policy_hash = sample_policy_hash(threshold);
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();
        let metadata = BatchMetadata::with_ids(Uuid::new_v4(), tenant_id, store_id, 0, 3);

        let mut builder = BatchWitnessBuilder::new()
            .metadata(metadata)
            .policy_hash(policy_hash)
            .policy_limit(threshold);

        for i in 0..4 {
            let amount = 5000;
            let inputs = sample_public_inputs(threshold, amount, i, tenant_id, store_id);
            builder = builder.add_event(5000, inputs).unwrap();
        }

        let witness = builder.build().unwrap();
        let trace_builder = BatchTraceBuilder::new(witness);
        let trace = trace_builder.build().unwrap();

        // Compliance accumulator should be 1 at last row (all compliant)
        let final_acc = trace.get(batch_cols::COMPLIANCE_ACCUMULATOR, trace.length() - 1);
        assert_eq!(final_acc, FELT_ONE);
    }

    #[test]
    fn test_batch_trace_builder_aml_threshold_boundary_rejects() {
        let threshold = 10_000u64;
        let policy_hash = sample_policy_hash(threshold);
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();
        let metadata = BatchMetadata::with_ids(Uuid::new_v4(), tenant_id, store_id, 0, 0);

        let mut builder = BatchWitnessBuilder::new()
            .metadata(metadata)
            .policy_hash(policy_hash)
            .policy_limit(threshold);

        // AML threshold is strict: amount == threshold must be non-compliant.
        builder = builder
            .add_event(
                threshold,
                sample_public_inputs(threshold, threshold, 0, tenant_id, store_id),
            )
            .unwrap();

        let witness = builder.build().unwrap();
        assert!(!witness.all_compliant());

        let trace_builder = BatchTraceBuilder::new(witness);
        let trace = trace_builder.build().unwrap();

        let final_acc = trace.get(batch_cols::COMPLIANCE_ACCUMULATOR, trace.length() - 1);
        assert_eq!(final_acc, FELT_ZERO);
    }

    #[test]
    fn test_batch_trace_builder_order_total_cap() {
        let cap = 10000u64;
        let policy_id = "order_total.cap";
        let policy_hash = sample_policy_hash_with_id(policy_id, PolicyParams::cap(cap));
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();
        let metadata = BatchMetadata::with_ids(Uuid::new_v4(), tenant_id, store_id, 0, 3);

        let mut builder = BatchWitnessBuilder::new()
            .metadata(metadata)
            .policy_hash(policy_hash)
            .policy_limit(cap);

        for i in 0..4 {
            let amount = 5_000 + i as u64 * 100;
            let inputs = sample_public_inputs_with_policy(
                policy_id,
                PolicyParams::cap(cap),
                amount,
                i,
                tenant_id,
                store_id,
            );
            builder = builder.add_event(amount, inputs).unwrap();
        }

        let witness = builder.build().unwrap();
        let trace_builder = BatchTraceBuilder::new(witness);
        let trace = trace_builder.build().unwrap();

        let final_acc = trace.get(batch_cols::COMPLIANCE_ACCUMULATOR, trace.length() - 1);
        assert_eq!(final_acc, FELT_ONE);
    }

    #[test]
    fn test_batch_trace_builder_order_total_cap_boundary() {
        let cap = 10_000u64;
        let policy_id = "order_total.cap";
        let policy_hash = sample_policy_hash_with_id(policy_id, PolicyParams::cap(cap));
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();
        let metadata = BatchMetadata::with_ids(Uuid::new_v4(), tenant_id, store_id, 0, 0);

        let mut builder = BatchWitnessBuilder::new()
            .metadata(metadata)
            .policy_hash(policy_hash)
            .policy_limit(cap);

        let inputs = sample_public_inputs_with_policy(
            policy_id,
            PolicyParams::cap(cap),
            cap,
            0,
            tenant_id,
            store_id,
        );
        builder = builder.add_event(cap, inputs).unwrap();

        let witness = builder.build().unwrap();
        let trace_builder = BatchTraceBuilder::new(witness);
        let trace = trace_builder.build().unwrap();

        let final_acc = trace.get(batch_cols::COMPLIANCE_ACCUMULATOR, trace.length() - 1);
        assert_eq!(final_acc, FELT_ONE);
    }

    #[test]
    fn test_single_event_finalize_output_matches_new_state_root() {
        let threshold = 10_000u64;
        let policy_hash = sample_policy_hash(threshold);
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();
        let metadata = BatchMetadata::with_ids(Uuid::new_v4(), tenant_id, store_id, 0, 0);

        let witness = BatchWitnessBuilder::new()
            .metadata(metadata)
            .policy_hash(policy_hash)
            .policy_limit(threshold)
            .add_event(
                5_000,
                sample_public_inputs(threshold, 5_000, 0, tenant_id, store_id),
            )
            .unwrap()
            .build()
            .unwrap();

        let new_root = witness.compute_new_state_root().unwrap();
        let trace = BatchTraceBuilder::new(witness).build().unwrap();
        let finalize_output_row = ROWS_PER_EVENT
            + leaf_row_count(1)
            + leaf_hash_row_count(1)
            + commitment_hash_row_count(1)
            + merkle_row_count(1)
            + FINALIZE_ROWS
            - 1;

        let mut finalize_state = [FELT_ZERO; RESCUE_STATE_WIDTH];
        for (lane, slot) in finalize_state.iter_mut().enumerate() {
            *slot = trace.get(batch_cols::merkle_rescue_state(lane), finalize_output_row);
        }

        assert_eq!(
            BatchStateRoot::collapse_finalize_state(&finalize_state),
            new_root.root
        );
        for (lane, expected) in new_root.root.iter().enumerate() {
            assert_eq!(
                trace.get(batch_cols::new_state_root(lane), finalize_output_row),
                *expected,
                "lane {lane} mismatch at finalize output row {finalize_output_row}"
            );
        }
    }
}
