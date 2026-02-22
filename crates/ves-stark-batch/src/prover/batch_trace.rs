//! Batch trace construction
//!
//! This module builds the execution trace for batch state transition proofs.
//! The trace extends the single-event compliance trace with batch-specific columns.

use rayon::prelude::*;
use ves_stark_air::policies::aml_threshold::compute_comparison_values;
use ves_stark_air::policies::order_total_cap::compute_comparison_values_lte;
use ves_stark_air::policy::ComparisonType;
use ves_stark_air::trace::cols as base_cols;
use ves_stark_primitives::rescue::{
    rescue_hash, rescue_permutation_trace, STATE_WIDTH as RESCUE_STATE_WIDTH,
};
use ves_stark_primitives::{felt_from_u64, Felt, FELT_ONE, FELT_ZERO};
use winter_math::FieldElement;
use winter_prover::TraceTable;

use crate::air::trace_layout::{
    batch_cols, calculate_trace_length, BatchPhase, BASE_TRACE_WIDTH, BATCH_TRACE_WIDTH,
    COMPLIANCE_ACC_GAMMA, FINALIZE_ROWS, ROWS_PER_EVENT, ROWS_PER_MERKLE_NODE,
};
use crate::error::BatchError;
use crate::prover::witness::{BatchEventWitness, BatchWitness};
use crate::state::{BatchStateRoot, EventMerkleTree};

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

/// Compute a Rescue hash commitment to the witness amount
fn compute_witness_commitment(amount_limbs: &[Felt; 8]) -> [Felt; RESCUE_STATE_WIDTH] {
    let hash_output = rescue_hash(amount_limbs);

    let mut state = [FELT_ZERO; RESCUE_STATE_WIDTH];
    state[0] = hash_output[0];
    state[1] = hash_output[1];
    state[2] = hash_output[2];
    state[3] = hash_output[3];

    state
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
        let policy_comparison = batch_policy.comparison_type();
        let policy_limit_limbs = batch_policy.limit_limbs();

        // Initialize trace columns
        let mut trace = vec![vec![FELT_ZERO; self.trace_length]; BATCH_TRACE_WIDTH];

        // Get batch-level data
        let batch_id = self.witness.batch_id_felts();
        let tenant_id = self.witness.tenant_id_felts();
        let store_id = self.witness.store_id_felts();
        let metadata_hash = self.witness.metadata.to_rescue_hash();

        // Build event Merkle tree and compute state roots
        let event_tree = self.witness.build_event_tree()?;
        let prev_state_root = &self.witness.prev_state_root;
        let new_state_root = self.witness.compute_new_state_root()?;

        // Process events in parallel
        let event_traces: Vec<_> = self
            .witness
            .events
            .par_iter()
            .map(|event| {
                self.build_event_trace(event, policy_comparison, &policy_limit_limbs)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Fill trace with event data
        let mut current_row = 0;
        let gamma = Felt::new(COMPLIANCE_ACC_GAMMA);
        let gamma_inv_pow_n = gamma.exp(self.witness.num_events() as u64).inv();
        let mut compliance_accumulator = gamma_inv_pow_n;

        for (event_idx, event_trace) in event_traces.iter().enumerate() {
            let event = &self.witness.events[event_idx];

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
                        filler_bit(row as u64)
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
                trace[batch_cols::EVENTS_DONE][row] = FELT_ZERO;
            }

            current_row += ROWS_PER_EVENT;
        }

        // Fill Merkle phase rows
        current_row = self.fill_merkle_trace(
            &mut trace,
            current_row,
            &event_tree,
            prev_state_root,
            &new_state_root,
            compliance_accumulator,
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
            &batch_id,
            &metadata_hash,
        );

        // Mark last row
        trace[batch_cols::IS_LAST_BATCH_ROW][self.trace_length - 1] = FELT_ONE;

        Ok(TraceTable::init(trace))
    }

    /// Build trace rows for a single event
    fn build_event_trace(
        &self,
        event: &BatchEventWitness,
        comparison: ComparisonType,
        limit_limbs: &[Felt; 8],
    ) -> Result<EventTraceData, BatchError> {
        let amount_limbs = event.amount_limbs();

        // Compute comparison values according to the event policy.
        let comparison_values = match comparison {
            ComparisonType::LessThan => compute_comparison_values(&amount_limbs, limit_limbs),
            ComparisonType::LessThanOrEqual => compute_comparison_values_lte(&amount_limbs, limit_limbs),
        };

        // Check compliance
        let final_comparison = comparison_values[7];
        if event.compliance_felt() != final_comparison {
            return Err(BatchError::EventNotCompliant {
                event_index: event.event_index,
                message: format!(
                    "Event {} compliance flag mismatch with comparison result",
                    event.event_index
                ),
            });
        }

        // Compute bit decomposition
        let limb0_bits = decompose_to_bits(amount_limbs[0]);
        let limb1_bits = decompose_to_bits(amount_limbs[1]);

        // Compute witness commitment
        let witness_commitment = compute_witness_commitment(&amount_limbs);

        // Build trace rows
        let mut base = vec![vec![FELT_ZERO; ROWS_PER_EVENT]; BASE_TRACE_WIDTH];

        for row in 0..ROWS_PER_EVENT {
            // Rescue state
            for i in 0..RESCUE_STATE_WIDTH {
                base[base_cols::RESCUE_STATE_START + i][row] = witness_commitment[i];
            }

            // Amount limbs
            for i in 0..8 {
                base[base_cols::AMOUNT_START + i][row] = amount_limbs[i];
            }

            // Threshold limbs
            for i in 0..8 {
                base[base_cols::THRESHOLD_START + i][row] = limit_limbs[i];
            }

            // Comparison values
            for i in 0..8 {
                base[base_cols::COMPARISON_START + i][row] = comparison_values[i];
            }

            // Bit decomposition
            for i in 0..32 {
                base[base_cols::AMOUNT_BITS_LIMB0_START + i][row] = limb0_bits[i];
            }
            for i in 0..32 {
                base[base_cols::AMOUNT_BITS_LIMB1_START + i][row] = limb1_bits[i];
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

        Ok(EventTraceData { base })
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
        batch_id: &[Felt; 4],
        tenant_id: &[Felt; 4],
        store_id: &[Felt; 4],
        metadata_hash: &[Felt; 4],
    ) -> usize {
        let levels = event_tree.levels();
        let mut current_row = start_row;

        for (level_idx, level) in levels.iter().enumerate() {
            for (node_idx, node) in level.iter().enumerate() {
                if current_row >= self.trace_length {
                    return current_row;
                }

                let (left_child, right_child) =
                    if let Some(children) = event_tree.level(level_idx) {
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
                for i in 0..4 {
                    hash_state[i] = left_child[i];
                    hash_state[4 + i] = right_child[i];
                }
                let trace_rows = rescue_permutation_trace(&hash_state);

                for step in 0..ROWS_PER_MERKLE_NODE {
                    let row = current_row + step;
                    if row >= self.trace_length {
                        break;
                    }

                    for i in 0..RESCUE_STATE_WIDTH {
                        trace[batch_cols::merkle_rescue_state(i)][row] = trace_rows[step][i];
                    }
                    trace[batch_cols::MERKLE_HASH_STEP][row] = felt_from_u64(step as u64);
                    trace[batch_cols::IS_FINALIZE_HASH][row] = FELT_ZERO;
                    trace[batch_cols::IS_MERKLE_ROW][row] = FELT_ONE;
                    trace[batch_cols::BATCH_PHASE][row] = BatchPhase::Merkle.to_felt();

                    trace[batch_cols::MERKLE_LEVEL][row] = felt_from_u64(level_idx as u64);
                    trace[batch_cols::MERKLE_NODE_INDEX][row] = felt_from_u64(node_idx as u64);

                    for i in 0..4 {
                        trace[batch_cols::merkle_output(i)][row] = node[i];
                        trace[batch_cols::merkle_left(i)][row] = left_child[i];
                        trace[batch_cols::merkle_right(i)][row] = right_child[i];
                    }

                    for i in 0..4 {
                        trace[batch_cols::prev_state_root(i)][row] = prev_state_root.root[i];
                        trace[batch_cols::new_state_root(i)][row] = new_state_root.root[i];
                        trace[batch_cols::event_tree_root(i)][row] = event_tree.root()[i];
                    }

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
                        trace[batch_cols::POLICY_HASH_START + i][row] =
                            self.witness.policy_hash[i];
                    }
                    trace[batch_cols::POLICY_LIMIT][row] =
                        felt_from_u64(self.witness.policy_limit);

                    trace[batch_cols::NUM_EVENTS][row] =
                        felt_from_u64(self.witness.num_events() as u64);
                    trace[batch_cols::EVENT_INDEX][row] =
                        felt_from_u64(self.witness.num_events() as u64);
                    trace[batch_cols::EVENT_ROW][row] = FELT_ZERO;
                    trace[batch_cols::EVENTS_DONE][row] = FELT_ONE;
                }

                current_row += ROWS_PER_MERKLE_NODE;
            }
        }

        current_row
    }

    /// Fill finalization rows (ROWS_PER_MERKLE_NODE rows).
    ///
    /// The finalization phase represents:
    ///   new_state_root = Rescue(event_tree_root || metadata_hash)
    #[allow(clippy::too_many_arguments)]
    fn fill_finalize_trace(
        &self,
        trace: &mut [Vec<Felt>],
        start_row: usize,
        prev_state_root: &BatchStateRoot,
        new_state_root: &BatchStateRoot,
        event_tree: &EventMerkleTree,
        compliance_accumulator: Felt,
        batch_id: &[Felt; 4],
        tenant_id: &[Felt; 4],
        store_id: &[Felt; 4],
        metadata_hash: &[Felt; 4],
    ) -> usize {
        let mut current_row = start_row;

        let mut hash_state = [FELT_ZERO; RESCUE_STATE_WIDTH];
        for i in 0..4 {
            hash_state[i] = event_tree.root()[i];
            hash_state[4 + i] = metadata_hash[i];
        }
        let trace_rows = rescue_permutation_trace(&hash_state);

        for step in 0..FINALIZE_ROWS {
            let row = current_row;
            if row >= self.trace_length {
                break;
            }

            for i in 0..RESCUE_STATE_WIDTH {
                trace[batch_cols::merkle_rescue_state(i)][row] = trace_rows[step][i];
            }
            for i in 0..4 {
                trace[batch_cols::merkle_output(i)][row] = new_state_root.root[i];
            }

            trace[batch_cols::MERKLE_HASH_STEP][row] = felt_from_u64(step as u64);
            trace[batch_cols::IS_FINALIZE_HASH][row] = FELT_ONE;
            trace[batch_cols::IS_MERKLE_ROW][row] = FELT_ZERO;
            trace[batch_cols::BATCH_PHASE][row] = BatchPhase::Finalize.to_felt();

            for i in 0..4 {
                trace[batch_cols::prev_state_root(i)][row] = prev_state_root.root[i];
                trace[batch_cols::new_state_root(i)][row] = new_state_root.root[i];
                trace[batch_cols::event_tree_root(i)][row] = event_tree.root()[i];
            }

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
            trace[batch_cols::NUM_EVENTS][row] =
                felt_from_u64(self.witness.num_events() as u64);
            trace[batch_cols::EVENT_INDEX][row] =
                felt_from_u64(self.witness.num_events() as u64);
            trace[batch_cols::EVENT_ROW][row] = FELT_ZERO;
            trace[batch_cols::EVENTS_DONE][row] = FELT_ONE;

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
        batch_id: &[Felt; 4],
        metadata_hash: &[Felt; 4],
    ) {
        let tenant_id = self.witness.tenant_id_felts();
        let store_id = self.witness.store_id_felts();

        for row in start_row..self.trace_length {
            trace[batch_cols::BATCH_PHASE][row] = BatchPhase::Padding.to_felt();
            trace[batch_cols::IS_MERKLE_ROW][row] = FELT_ZERO;
            trace[batch_cols::IS_FINALIZE_HASH][row] = FELT_ZERO;
            trace[batch_cols::MERKLE_HASH_STEP][row] = FELT_ZERO;

            // State roots (constant)
            for i in 0..4 {
                trace[batch_cols::prev_state_root(i)][row] = prev_state_root.root[i];
                trace[batch_cols::new_state_root(i)][row] = new_state_root.root[i];
                trace[batch_cols::event_tree_root(i)][row] = event_tree.root()[i];
            }

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::witness::BatchWitnessBuilder;
    use crate::state::BatchMetadata;
    use uuid::Uuid;
    use ves_stark_primitives::public_inputs::{
        compute_policy_hash, witness_commitment_u64_to_hex, CompliancePublicInputs, PolicyParams,
    };
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
        let metadata =
            BatchMetadata::with_ids(Uuid::new_v4(), tenant_id, store_id, 0, 7);

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
        let metadata =
            BatchMetadata::with_ids(Uuid::new_v4(), tenant_id, store_id, 0, 3);

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
        let metadata =
            BatchMetadata::with_ids(Uuid::new_v4(), tenant_id, store_id, 0, 3);

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
        let metadata =
            BatchMetadata::with_ids(Uuid::new_v4(), tenant_id, store_id, 0, 0);

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
        let metadata =
            BatchMetadata::with_ids(Uuid::new_v4(), tenant_id, store_id, 0, 3);

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
            builder = builder
                .add_event(amount, inputs)
                .unwrap();
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
        let metadata =
            BatchMetadata::with_ids(Uuid::new_v4(), tenant_id, store_id, 0, 0);

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
}
