//! Batch trace construction
//!
//! This module builds the execution trace for batch state transition proofs.
//! The trace extends the single-event compliance trace with batch-specific columns.

use rayon::prelude::*;
use ves_stark_air::policies::aml_threshold::compute_comparison_values;
use ves_stark_air::trace::cols as base_cols;
use ves_stark_primitives::rescue::{rescue_hash, STATE_WIDTH as RESCUE_STATE_WIDTH};
use ves_stark_primitives::{felt_from_u64, Felt, FELT_ONE, FELT_ZERO};
use winter_prover::TraceTable;

use crate::air::trace_layout::{
    batch_cols, calculate_trace_length, BatchPhase, BASE_TRACE_WIDTH, BATCH_TRACE_WIDTH,
    MIN_BATCH_TRACE_LENGTH, ROWS_PER_EVENT,
};
use crate::error::BatchError;
use crate::prover::witness::{BatchEventWitness, BatchWitness};
use crate::state::{BatchStateRoot, EventMerkleTree};

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

/// Get limit limbs from threshold
fn limit_limbs(limit: u64) -> [Felt; 8] {
    let mut limbs = [FELT_ZERO; 8];
    limbs[0] = felt_from_u64(limit & 0xFFFFFFFF);
    limbs[1] = felt_from_u64(limit >> 32);
    limbs
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
        self.trace_length = length.next_power_of_two().max(MIN_BATCH_TRACE_LENGTH);
        self
    }

    /// Build the execution trace
    pub fn build(self) -> Result<TraceTable<Felt>, BatchError> {
        // Validate witness
        self.witness.validate()?;

        // Initialize trace columns
        let mut trace = vec![vec![FELT_ZERO; self.trace_length]; BATCH_TRACE_WIDTH];

        // Get batch-level data
        let limit_limbs = limit_limbs(self.witness.policy_limit);
        let batch_id = self.witness.batch_id_felts();
        let tenant_id = self.witness.tenant_id_felts();
        let store_id = self.witness.store_id_felts();
        let metadata_hash = self.witness.metadata.to_rescue_hash();

        // Build event Merkle tree and compute state roots
        let event_tree = self.witness.build_event_tree();
        let prev_state_root = &self.witness.prev_state_root;
        let new_state_root = self.witness.compute_new_state_root();

        // Process events in parallel
        let event_traces: Vec<_> = self
            .witness
            .events
            .par_iter()
            .map(|event| self.build_event_trace(event, &limit_limbs))
            .collect::<Result<Vec<_>, _>>()?;

        // Fill trace with event data
        let mut current_row = 0;
        let mut compliance_accumulator = FELT_ONE;

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
                    compliance_accumulator = felt_from_u64(
                        compliance_accumulator.as_int() * event.compliance_felt().as_int(),
                    );
                }
                trace[batch_cols::COMPLIANCE_ACCUMULATOR][row] = compliance_accumulator;
                trace[batch_cols::EVENT_COMPLIANCE_FLAG][row] = event.compliance_felt();

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

                // Control flags
                trace[batch_cols::IS_FIRST_BATCH_ROW][row] =
                    if row == 0 { FELT_ONE } else { FELT_ZERO };
                trace[batch_cols::IS_MERKLE_ROW][row] = FELT_ZERO;
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
        limit_limbs: &[Felt; 8],
    ) -> Result<EventTraceData, BatchError> {
        let amount_limbs = event.amount_limbs();

        // Compute comparison values (using LT for AML threshold)
        let comparison_values = compute_comparison_values(&amount_limbs, limit_limbs);

        // Check compliance
        let final_comparison = comparison_values[7];
        if event.is_compliant && final_comparison != FELT_ONE {
            return Err(BatchError::EventNotCompliant {
                event_index: event.event_index,
                message: format!(
                    "Event {} marked compliant but comparison failed",
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

    /// Fill Merkle tree computation rows
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

                // Set Merkle columns
                trace[batch_cols::MERKLE_LEVEL][current_row] = felt_from_u64(level_idx as u64);
                trace[batch_cols::MERKLE_NODE_INDEX][current_row] = felt_from_u64(node_idx as u64);
                trace[batch_cols::IS_MERKLE_ROW][current_row] = FELT_ONE;
                trace[batch_cols::BATCH_PHASE][current_row] = BatchPhase::Merkle.to_felt();

                // Output (this node's hash)
                for i in 0..4 {
                    trace[batch_cols::merkle_output(i)][current_row] = node[i];
                }

                // State roots (constant)
                for i in 0..4 {
                    trace[batch_cols::prev_state_root(i)][current_row] = prev_state_root.root[i];
                    trace[batch_cols::new_state_root(i)][current_row] = new_state_root.root[i];
                    trace[batch_cols::event_tree_root(i)][current_row] = event_tree.root()[i];
                }

                // Accumulator and compliance
                trace[batch_cols::COMPLIANCE_ACCUMULATOR][current_row] = compliance_accumulator;
                trace[batch_cols::EVENT_COMPLIANCE_FLAG][current_row] = compliance_accumulator;

                // Metadata
                for i in 0..4 {
                    trace[batch_cols::batch_id(i)][current_row] = batch_id[i];
                    trace[batch_cols::metadata_hash(i)][current_row] = metadata_hash[i];
                }
                for i in 0..4 {
                    trace[batch_cols::TENANT_ID_START + i][current_row] = tenant_id[i];
                    trace[batch_cols::STORE_ID_START + i][current_row] = store_id[i];
                }
                trace[batch_cols::SEQUENCE_START][current_row] =
                    felt_from_u64(self.witness.metadata.sequence_start);
                trace[batch_cols::SEQUENCE_END][current_row] =
                    felt_from_u64(self.witness.metadata.sequence_end);
                trace[batch_cols::TIMESTAMP][current_row] =
                    felt_from_u64(self.witness.metadata.timestamp);

                // Event info (constant from last event)
                trace[batch_cols::NUM_EVENTS][current_row] =
                    felt_from_u64(self.witness.num_events() as u64);
                trace[batch_cols::EVENT_INDEX][current_row] =
                    felt_from_u64((self.witness.num_events() - 1) as u64);

                current_row += 1;
            }
        }

        current_row
    }

    /// Fill finalization rows
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
        let finalize_rows = 4;
        let mut current_row = start_row;

        for _row_in_finalize in 0..finalize_rows {
            if current_row >= self.trace_length {
                return current_row;
            }

            trace[batch_cols::BATCH_PHASE][current_row] = BatchPhase::Finalize.to_felt();
            trace[batch_cols::IS_MERKLE_ROW][current_row] = FELT_ZERO;

            // State roots
            for i in 0..4 {
                trace[batch_cols::prev_state_root(i)][current_row] = prev_state_root.root[i];
                trace[batch_cols::new_state_root(i)][current_row] = new_state_root.root[i];
                trace[batch_cols::event_tree_root(i)][current_row] = event_tree.root()[i];
            }

            // Compliance
            trace[batch_cols::COMPLIANCE_ACCUMULATOR][current_row] = compliance_accumulator;
            trace[batch_cols::EVENT_COMPLIANCE_FLAG][current_row] = compliance_accumulator;

            // Metadata
            for i in 0..4 {
                trace[batch_cols::batch_id(i)][current_row] = batch_id[i];
                trace[batch_cols::metadata_hash(i)][current_row] = metadata_hash[i];
            }
            for i in 0..4 {
                trace[batch_cols::TENANT_ID_START + i][current_row] = tenant_id[i];
                trace[batch_cols::STORE_ID_START + i][current_row] = store_id[i];
            }
            trace[batch_cols::SEQUENCE_START][current_row] =
                felt_from_u64(self.witness.metadata.sequence_start);
            trace[batch_cols::SEQUENCE_END][current_row] =
                felt_from_u64(self.witness.metadata.sequence_end);
            trace[batch_cols::TIMESTAMP][current_row] =
                felt_from_u64(self.witness.metadata.timestamp);
            trace[batch_cols::NUM_EVENTS][current_row] =
                felt_from_u64(self.witness.num_events() as u64);
            trace[batch_cols::EVENT_INDEX][current_row] =
                felt_from_u64((self.witness.num_events() - 1) as u64);

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
        for row in start_row..self.trace_length {
            trace[batch_cols::BATCH_PHASE][row] = BatchPhase::Padding.to_felt();
            trace[batch_cols::IS_MERKLE_ROW][row] = FELT_ZERO;

            // State roots (constant)
            for i in 0..4 {
                trace[batch_cols::prev_state_root(i)][row] = prev_state_root.root[i];
                trace[batch_cols::new_state_root(i)][row] = new_state_root.root[i];
                trace[batch_cols::event_tree_root(i)][row] = event_tree.root()[i];
            }

            // Compliance (constant)
            trace[batch_cols::COMPLIANCE_ACCUMULATOR][row] = compliance_accumulator;
            trace[batch_cols::EVENT_COMPLIANCE_FLAG][row] = compliance_accumulator;

            // Metadata (constant)
            for i in 0..4 {
                trace[batch_cols::batch_id(i)][row] = batch_id[i];
                trace[batch_cols::metadata_hash(i)][row] = metadata_hash[i];
            }

            // Event info
            trace[batch_cols::NUM_EVENTS][row] = felt_from_u64(self.witness.num_events() as u64);
            trace[batch_cols::EVENT_INDEX][row] =
                felt_from_u64((self.witness.num_events() - 1) as u64);
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
        compute_policy_hash, CompliancePublicInputs, PolicyParams,
    };
    use winter_prover::Trace;

    fn sample_public_inputs(threshold: u64, idx: usize) -> CompliancePublicInputs {
        let policy_id = "aml.threshold";
        let params = PolicyParams::threshold(threshold);
        let hash = compute_policy_hash(policy_id, &params).unwrap();

        CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            sequence_number: idx as u64,
            payload_kind: 1,
            payload_plain_hash: "0".repeat(64),
            payload_cipher_hash: "0".repeat(64),
            event_signing_hash: "0".repeat(64),
            policy_id: policy_id.to_string(),
            policy_params: params,
            policy_hash: hash.to_hex(),
        }
    }

    fn sample_policy_hash(threshold: u64) -> [Felt; 8] {
        let policy_id = "aml.threshold";
        let params = PolicyParams::threshold(threshold);
        let hash = compute_policy_hash(policy_id, &params).unwrap();
        ves_stark_primitives::hash_to_felts(&hash)
    }

    #[test]
    fn test_batch_trace_builder_small() {
        let threshold = 10000u64;
        let policy_hash = sample_policy_hash(threshold);
        let metadata =
            BatchMetadata::with_ids(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), 0, 7);

        let mut builder = BatchWitnessBuilder::new()
            .metadata(metadata)
            .policy_hash(policy_hash)
            .policy_limit(threshold);

        // Add 8 compliant events
        for i in 0..8 {
            let inputs = sample_public_inputs(threshold, i);
            builder = builder.add_event(5000 + i as u64 * 100, inputs);
        }

        let witness = builder.build().unwrap();
        let trace_builder = BatchTraceBuilder::new(witness);
        let trace = trace_builder.build().unwrap();

        assert_eq!(trace.width(), BATCH_TRACE_WIDTH);
        assert!(trace.length() >= MIN_BATCH_TRACE_LENGTH);
    }

    #[test]
    fn test_batch_trace_state_roots() {
        let threshold = 10000u64;
        let policy_hash = sample_policy_hash(threshold);
        let metadata =
            BatchMetadata::with_ids(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), 0, 3);

        let mut builder = BatchWitnessBuilder::new()
            .metadata(metadata)
            .policy_hash(policy_hash)
            .policy_limit(threshold);

        for i in 0..4 {
            let inputs = sample_public_inputs(threshold, i);
            builder = builder.add_event(5000, inputs);
        }

        let witness = builder.build().unwrap();
        let new_root = witness.compute_new_state_root();

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
        let metadata =
            BatchMetadata::with_ids(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), 0, 3);

        let mut builder = BatchWitnessBuilder::new()
            .metadata(metadata)
            .policy_hash(policy_hash)
            .policy_limit(threshold);

        for i in 0..4 {
            let inputs = sample_public_inputs(threshold, i);
            builder = builder.add_event(5000, inputs);
        }

        let witness = builder.build().unwrap();
        let trace_builder = BatchTraceBuilder::new(witness);
        let trace = trace_builder.build().unwrap();

        // Compliance accumulator should be 1 at last row (all compliant)
        let final_acc = trace.get(batch_cols::COMPLIANCE_ACCUMULATOR, trace.length() - 1);
        assert_eq!(final_acc, FELT_ONE);
    }
}
