//! Extended trace layout for batch proofs
//!
//! The batch trace extends the single-event compliance trace
//! with additional columns for:
//! - Event indexing
//! - Merkle tree computation
//! - State root tracking
//! - Batch metadata

use ves_stark_air::trace::cols as base_cols;
use ves_stark_primitives::Felt;

/// Width of the "base" portion of the batch trace that mirrors the single-event compliance trace.
///
/// This is intentionally **not** `ves_stark_air::trace::TRACE_WIDTH` (which includes extra columns
/// for public input binding and additional gadgets). The batch trace currently only needs the
/// original columns up through the Rescue commitment flag, and keeping the width small is required
/// to stay under Winterfell's 255-column trace limit.
pub const BASE_TRACE_WIDTH: usize = base_cols::RESCUE_COMMIT_FLAG + 1;

/// Total width of the batch execution trace
pub const BATCH_TRACE_WIDTH: usize = batch_cols::RESERVED + 1;

/// Number of batch-specific columns added after the base compliance trace.
pub const BATCH_EXTENSION_WIDTH: usize = BATCH_TRACE_WIDTH - BASE_TRACE_WIDTH;

/// Minimum trace length for batch proofs
pub const MIN_BATCH_TRACE_LENGTH: usize = 256;

/// Maximum number of events per batch
pub const MAX_BATCH_SIZE: usize = 128;

/// Rows needed per event for compliance verification
pub const ROWS_PER_EVENT: usize = 4;

/// Rows per Merkle tree node.
///
/// Rescue hashing uses 14 half-rounds plus 1 output row in the in-circuit
/// permutation trace.
pub const ROWS_PER_MERKLE_NODE: usize = 15;

/// Rows per amount-commitment hash segment.
///
/// Amount commitments absorb exactly 8 limbs, so each real event needs one Rescue permutation.
pub const ROWS_PER_COMMITMENT_HASH: usize = ROWS_PER_MERKLE_NODE;

/// Rows per leaf-hash segment.
///
/// Event leaves absorb 25 elements, so they require 4 Rescue sponge permutations:
/// - chunk 0: `event_id || amount_commitment`
/// - chunk 1: `policy_hash`
/// - chunk 2: `public_inputs_hash`
/// - chunk 3: `compliance_flag`
pub const ROWS_PER_LEAF_HASH: usize = ROWS_PER_MERKLE_NODE * 4;

/// Rows for finalization phase.
///
/// The state root hash uses the same Rescue transition structure as Merkle nodes:
/// 14 half-rounds plus output.
pub const FINALIZE_ROWS: usize = 15;

/// Multiplicative factor used in the batch compliance accumulator update.
///
/// See `BatchComplianceAir` for how this is used to keep the accumulator non-constant in the
/// all-compliant case without changing the final boolean output.
pub const COMPLIANCE_ACC_GAMMA: u64 = 7;

/// Multiplicative factor used by the Merkle linkage sequence accumulators.
pub const MERKLE_LINK_GAMMA: u64 = 11;

/// Fixed non-zero tags mixed into the amount-limb streams.
///
/// These keep the per-lane accumulators non-degenerate even when a lane is zero across a batch
/// (for example, when all amounts fit into a single 32-bit limb).
pub const AMOUNT_STREAM_LANE_TAGS: [u64; 2] = [1, 2];

/// Column indices for the batch trace
pub mod batch_cols {
    use super::BASE_TRACE_WIDTH;

    // =========================================================================
    // Base compliance columns (0..BASE_TRACE_WIDTH)
    // These are inherited from the single-event compliance AIR
    // =========================================================================
    pub const BASE_TRACE_END: usize = BASE_TRACE_WIDTH;

    // =========================================================================
    // Event indexing (BASE_TRACE_END..BASE_TRACE_END+2)
    // =========================================================================
    /// Current event index in the batch (0 to N-1)
    pub const EVENT_INDEX: usize = BASE_TRACE_END;

    /// Total number of events in batch
    pub const NUM_EVENTS: usize = EVENT_INDEX + 1;

    // =========================================================================
    // Merkle / hash columns
    // Used during commitment hashing, Merkle tree construction, and finalization
    // =========================================================================
    /// Merkle left child (4 elements)
    pub const MERKLE_LEFT_START: usize = NUM_EVENTS + 1;
    pub const MERKLE_LEFT_END: usize = MERKLE_LEFT_START + 4;

    /// Event-phase subtraction witness aliases.
    ///
    /// Event rows and Merkle rows are disjoint, so the first four Merkle-left
    /// columns are reused while processing events to store:
    /// - diff limb 0
    /// - diff limb 1
    /// - borrow 0
    /// - borrow 1
    pub const EVENT_DIFF0: usize = MERKLE_LEFT_START;
    pub const EVENT_DIFF1: usize = MERKLE_LEFT_START + 1;
    pub const EVENT_BORROW0: usize = MERKLE_LEFT_START + 2;
    pub const EVENT_BORROW1: usize = MERKLE_LEFT_START + 3;

    /// Merkle right child (4 elements)
    ///
    /// Event rows and leaf rows reuse these columns as an event-side accumulator for the
    /// ordered leaf-hash stream before Merkle hashing begins.
    pub const MERKLE_RIGHT_START: usize = MERKLE_LEFT_END;
    pub const MERKLE_RIGHT_END: usize = MERKLE_RIGHT_START + 4;

    /// Merkle parent/output (4 elements)
    pub const MERKLE_OUTPUT_START: usize = MERKLE_RIGHT_END;
    pub const MERKLE_OUTPUT_END: usize = MERKLE_OUTPUT_START + 4;

    /// Current Merkle tree level (0 = leaves)
    pub const MERKLE_LEVEL: usize = MERKLE_OUTPUT_END;

    /// Index within current level
    pub const MERKLE_NODE_INDEX: usize = MERKLE_LEVEL + 1;

    /// Number of nodes in the current Merkle level.
    pub const MERKLE_LEVEL_SIZE: usize = MERKLE_NODE_INDEX + 1;

    /// Flag: is this a level-0 leaf row?
    pub const IS_LEAF_ROW: usize = MERKLE_LEVEL_SIZE + 1;

    /// Flag: is this a real-event amount-commitment hash row?
    pub const IS_COMMITMENT_HASH_ROW: usize = IS_LEAF_ROW + 1;

    /// Flag: is this a real-event leaf-hash row?
    pub const IS_LEAF_HASH_ROW: usize = IS_COMMITMENT_HASH_ROW + 1;

    /// Flag: is this a Merkle computation row?
    pub const IS_MERKLE_ROW: usize = IS_LEAF_HASH_ROW + 1;

    /// Final event tree root (4 elements) - stored after Merkle phase
    pub const EVENT_TREE_ROOT_START: usize = IS_MERKLE_ROW + 1;
    pub const EVENT_TREE_ROOT_END: usize = EVENT_TREE_ROOT_START + 4;

    // =========================================================================
    // State root columns
    // =========================================================================
    /// Running accumulator for the event segment's claimed leaf amount commitments (4 lanes).
    pub const EVENT_COMMITMENT_ACC_START: usize = EVENT_TREE_ROOT_END;
    pub const EVENT_COMMITMENT_ACC_END: usize = EVENT_COMMITMENT_ACC_START + 4;

    /// Running accumulator for the explicit leaf rows' amount commitments (4 lanes).
    pub const LEAF_COMMITMENT_ACC_START: usize = EVENT_COMMITMENT_ACC_END;
    pub const LEAF_COMMITMENT_ACC_END: usize = LEAF_COMMITMENT_ACC_START + 4;

    /// Running accumulator for the event segment's claimed leaf event IDs (4 lanes).
    pub const EVENT_ID_ACC_START: usize = LEAF_COMMITMENT_ACC_END;
    pub const EVENT_ID_ACC_END: usize = EVENT_ID_ACC_START + 4;

    /// Running accumulator for the explicit leaf rows' event IDs (4 lanes).
    pub const LEAF_ID_ACC_START: usize = EVENT_ID_ACC_END;
    pub const LEAF_ID_ACC_END: usize = LEAF_ID_ACC_START + 4;

    /// Running accumulator for the event segment's claimed leaf policy hash lanes (8 lanes).
    pub const EVENT_POLICY_ACC_START: usize = LEAF_ID_ACC_END;
    pub const EVENT_POLICY_ACC_END: usize = EVENT_POLICY_ACC_START + 8;

    /// Running accumulator for the explicit leaf rows' policy hash lanes (8 lanes).
    pub const LEAF_POLICY_ACC_START: usize = EVENT_POLICY_ACC_END;
    pub const LEAF_POLICY_ACC_END: usize = LEAF_POLICY_ACC_START + 8;

    /// Running accumulator for the event segment's claimed canonical public-input hash lanes.
    pub const EVENT_PUBLIC_INPUTS_ACC_START: usize = LEAF_POLICY_ACC_END;
    pub const EVENT_PUBLIC_INPUTS_ACC_END: usize = EVENT_PUBLIC_INPUTS_ACC_START + 8;

    /// Running accumulator for the explicit leaf rows' canonical public-input hash lanes.
    pub const LEAF_PUBLIC_INPUTS_ACC_START: usize = EVENT_PUBLIC_INPUTS_ACC_END;
    pub const LEAF_PUBLIC_INPUTS_ACC_END: usize = LEAF_PUBLIC_INPUTS_ACC_START + 8;

    /// Running accumulator for the event segment's claimed amount limbs (2 lanes).
    pub const EVENT_AMOUNT_ACC_START: usize = LEAF_PUBLIC_INPUTS_ACC_END;
    pub const EVENT_AMOUNT_ACC_END: usize = EVENT_AMOUNT_ACC_START + 2;

    /// Running accumulator for the explicit leaf rows' amount limbs (2 lanes).
    pub const LEAF_AMOUNT_ACC_START: usize = EVENT_AMOUNT_ACC_END;
    pub const LEAF_AMOUNT_ACC_END: usize = LEAF_AMOUNT_ACC_START + 2;

    /// Running accumulator for the event segment's claimed compliance flags.
    pub const EVENT_FLAG_ACC: usize = LEAF_AMOUNT_ACC_END;

    /// Running accumulator for the explicit leaf rows' compliance flags.
    pub const LEAF_FLAG_ACC: usize = EVENT_FLAG_ACC + 1;

    /// Running sequence accumulator for the previous level's outputs (4 lanes).
    pub const MERKLE_PREV_LEVEL_ACC_START: usize = LEAF_FLAG_ACC + 1;
    pub const MERKLE_PREV_LEVEL_ACC_END: usize = MERKLE_PREV_LEVEL_ACC_START + 4;

    /// Running sequence accumulator for the current level's consumed children (4 lanes).
    pub const MERKLE_CONSUMED_LEVEL_ACC_START: usize = MERKLE_PREV_LEVEL_ACC_END;
    pub const MERKLE_CONSUMED_LEVEL_ACC_END: usize = MERKLE_CONSUMED_LEVEL_ACC_START + 4;

    /// Running sequence accumulator for the current level's produced outputs (4 lanes).
    pub const MERKLE_CURR_LEVEL_ACC_START: usize = MERKLE_CONSUMED_LEVEL_ACC_END;
    pub const MERKLE_CURR_LEVEL_ACC_END: usize = MERKLE_CURR_LEVEL_ACC_START + 4;

    /// Previous batch state root (4 elements)
    pub const PREV_STATE_ROOT_START: usize = MERKLE_CURR_LEVEL_ACC_END;
    pub const PREV_STATE_ROOT_END: usize = PREV_STATE_ROOT_START + 4;

    /// New batch state root (4 elements)
    pub const NEW_STATE_ROOT_START: usize = PREV_STATE_ROOT_END;
    pub const NEW_STATE_ROOT_END: usize = NEW_STATE_ROOT_START + 4;

    // =========================================================================
    // Compliance accumulator
    // =========================================================================
    /// Running AND of all compliance flags
    ///
    /// Internally, the trace scales updates by `COMPLIANCE_ACC_GAMMA` and initializes the column
    /// to `GAMMA^{-num_events}` so that:
    /// - the accumulator is non-constant even when all events are compliant
    /// - the final value is still a boolean: `1` if all flags are 1, else `0`
    pub const COMPLIANCE_ACCUMULATOR: usize = NEW_STATE_ROOT_END;

    /// Per-event compliance flag consumed by the AIR on a specific row within each event.
    ///
    /// On other rows (where the flag is not read by constraints), the trace may contain arbitrary
    /// binary filler values.
    pub const EVENT_COMPLIANCE_FLAG: usize = COMPLIANCE_ACCUMULATOR + 1;

    // =========================================================================
    // Batch phase and control
    // =========================================================================
    /// Current phase
    ///
    /// Encoding:
    /// - 0 = event
    /// - 1 = leaf
    /// - 2 = leaf-hash
    /// - 3 = commitment-hash
    /// - 4 = merkle
    /// - 5 = finalize
    /// - 6 = padding
    pub const BATCH_PHASE: usize = EVENT_COMPLIANCE_FLAG + 1;

    /// Row within current event
    pub const EVENT_ROW: usize = BATCH_PHASE + 1;

    /// Is this the first row of the trace?
    pub const IS_FIRST_BATCH_ROW: usize = EVENT_ROW + 1;

    /// Is this the last row of the trace?
    pub const IS_LAST_BATCH_ROW: usize = IS_FIRST_BATCH_ROW + 1;

    // =========================================================================
    // Batch metadata
    // =========================================================================
    /// Batch ID (4 elements)
    pub const BATCH_ID_START: usize = IS_LAST_BATCH_ROW + 1;
    pub const BATCH_ID_END: usize = BATCH_ID_START + 4;

    /// Tenant ID (4 elements)
    pub const TENANT_ID_START: usize = BATCH_ID_END;
    pub const TENANT_ID_END: usize = TENANT_ID_START + 4;

    /// Store ID (4 elements)
    pub const STORE_ID_START: usize = TENANT_ID_END;
    pub const STORE_ID_END: usize = STORE_ID_START + 4;

    /// Sequence start
    pub const SEQUENCE_START: usize = STORE_ID_END;

    /// Sequence end
    pub const SEQUENCE_END: usize = SEQUENCE_START + 1;

    /// Timestamp
    pub const TIMESTAMP: usize = SEQUENCE_END + 1;

    /// Metadata hash (4 elements)
    pub const METADATA_HASH_START: usize = TIMESTAMP + 1;
    pub const METADATA_HASH_END: usize = METADATA_HASH_START + 4;

    // =========================================================================
    // Policy fields (bound to public inputs)
    // =========================================================================
    /// Policy hash (8 elements)
    pub const POLICY_HASH_START: usize = METADATA_HASH_END;
    pub const POLICY_HASH_END: usize = POLICY_HASH_START + 8;

    /// Policy limit (threshold/cap, in the base field)
    pub const POLICY_LIMIT: usize = POLICY_HASH_END;

    // =========================================================================
    // Events Done (last column)
    // =========================================================================
    /// Flag indicating the end of the event-processing segment of the trace.
    ///
    /// This is set to:
    /// - `0` for all rows corresponding to real events
    /// - `1` starting immediately after the last event, and must remain `1` for the remainder
    ///
    /// The AIR uses this to ensure the compliance accumulator is updated exactly once per event
    /// (and never during Merkle/finalize/padding rows).
    pub const EVENTS_DONE: usize = POLICY_LIMIT + 1;

    // =========================================================================
    // In-circuit Rescue hash state (for commitment, Merkle, and finalize phases)
    // =========================================================================
    /// Rescue permutation state during amount-commitment hashing, Merkle hashing, and finalization.
    /// 12 columns tracking the full Rescue state through half-rounds.
    pub const MERKLE_RESCUE_STATE_START: usize = EVENTS_DONE + 1;
    pub const MERKLE_RESCUE_STATE_END: usize = MERKLE_RESCUE_STATE_START + 12;

    /// Step counter within a Rescue hash computation (0..14).
    /// Steps 0-13 are half-rounds; step 14 is the output row.
    pub const MERKLE_HASH_STEP: usize = MERKLE_RESCUE_STATE_END;

    /// Flag: is this row part of the finalize hash computation?
    pub const IS_FINALIZE_HASH: usize = MERKLE_HASH_STEP + 1;

    /// Reserved (last column) - alias for backward compatibility.
    pub const RESERVED: usize = IS_FINALIZE_HASH;

    // =========================================================================
    // Helper functions
    // =========================================================================

    /// Get Merkle left child elements
    #[inline]
    pub fn merkle_left(i: usize) -> usize {
        debug_assert!(i < 4);
        MERKLE_LEFT_START + i
    }

    /// Get event-phase subtraction diff limb columns.
    #[inline]
    pub fn event_diff(limb_idx: usize) -> usize {
        debug_assert!(limb_idx < 2);
        if limb_idx == 0 {
            EVENT_DIFF0
        } else {
            EVENT_DIFF1
        }
    }

    /// Get event-phase subtraction borrow columns.
    #[inline]
    pub fn event_borrow(idx: usize) -> usize {
        debug_assert!(idx < 2);
        if idx == 0 {
            EVENT_BORROW0
        } else {
            EVENT_BORROW1
        }
    }

    /// Get Merkle right child elements
    #[inline]
    pub fn merkle_right(i: usize) -> usize {
        debug_assert!(i < 4);
        MERKLE_RIGHT_START + i
    }

    /// Get Merkle output elements
    #[inline]
    pub fn merkle_output(i: usize) -> usize {
        debug_assert!(i < 4);
        MERKLE_OUTPUT_START + i
    }

    /// Get previous-level accumulator lane.
    #[inline]
    pub fn merkle_prev_level_acc(i: usize) -> usize {
        debug_assert!(i < 4);
        MERKLE_PREV_LEVEL_ACC_START + i
    }

    /// Get event-side amount-commitment accumulator lane.
    #[inline]
    pub fn event_commitment_acc(i: usize) -> usize {
        debug_assert!(i < 4);
        EVENT_COMMITMENT_ACC_START + i
    }

    /// Get leaf-side amount-commitment accumulator lane.
    #[inline]
    pub fn leaf_commitment_acc(i: usize) -> usize {
        debug_assert!(i < 4);
        LEAF_COMMITMENT_ACC_START + i
    }

    /// Get event-side event-ID accumulator lane.
    #[inline]
    pub fn event_id_acc(i: usize) -> usize {
        debug_assert!(i < 4);
        EVENT_ID_ACC_START + i
    }

    /// Get leaf-side event-ID accumulator lane.
    #[inline]
    pub fn leaf_id_acc(i: usize) -> usize {
        debug_assert!(i < 4);
        LEAF_ID_ACC_START + i
    }

    /// Get event-side policy-hash accumulator lane.
    #[inline]
    pub fn event_policy_acc(i: usize) -> usize {
        debug_assert!(i < 8);
        EVENT_POLICY_ACC_START + i
    }

    /// Get leaf-side policy-hash accumulator lane.
    #[inline]
    pub fn leaf_policy_acc(i: usize) -> usize {
        debug_assert!(i < 8);
        LEAF_POLICY_ACC_START + i
    }

    /// Get event-side canonical public-input hash accumulator lane.
    #[inline]
    pub fn event_public_inputs_acc(i: usize) -> usize {
        debug_assert!(i < 8);
        EVENT_PUBLIC_INPUTS_ACC_START + i
    }

    /// Get leaf-side canonical public-input hash accumulator lane.
    #[inline]
    pub fn leaf_public_inputs_acc(i: usize) -> usize {
        debug_assert!(i < 8);
        LEAF_PUBLIC_INPUTS_ACC_START + i
    }

    /// Get event-side amount-limb accumulator lane.
    #[inline]
    pub fn event_amount_acc(i: usize) -> usize {
        debug_assert!(i < 2);
        EVENT_AMOUNT_ACC_START + i
    }

    /// Get leaf-side amount-limb accumulator lane.
    #[inline]
    pub fn leaf_amount_acc(i: usize) -> usize {
        debug_assert!(i < 2);
        LEAF_AMOUNT_ACC_START + i
    }

    /// Get consumed-level accumulator lane.
    #[inline]
    pub fn merkle_consumed_level_acc(i: usize) -> usize {
        debug_assert!(i < 4);
        MERKLE_CONSUMED_LEVEL_ACC_START + i
    }

    /// Get current-level accumulator lane.
    #[inline]
    pub fn merkle_curr_level_acc(i: usize) -> usize {
        debug_assert!(i < 4);
        MERKLE_CURR_LEVEL_ACC_START + i
    }

    /// Get previous state root element
    #[inline]
    pub fn prev_state_root(i: usize) -> usize {
        debug_assert!(i < 4);
        PREV_STATE_ROOT_START + i
    }

    /// Get new state root element
    #[inline]
    pub fn new_state_root(i: usize) -> usize {
        debug_assert!(i < 4);
        NEW_STATE_ROOT_START + i
    }

    /// Get event tree root element
    #[inline]
    pub fn event_tree_root(i: usize) -> usize {
        debug_assert!(i < 4);
        EVENT_TREE_ROOT_START + i
    }

    /// Get batch ID element
    #[inline]
    pub fn batch_id(i: usize) -> usize {
        debug_assert!(i < 4);
        BATCH_ID_START + i
    }

    /// Get metadata hash element
    #[inline]
    pub fn metadata_hash(i: usize) -> usize {
        debug_assert!(i < 4);
        METADATA_HASH_START + i
    }

    /// Get Merkle Rescue state element
    #[inline]
    pub fn merkle_rescue_state(i: usize) -> usize {
        debug_assert!(i < 12);
        MERKLE_RESCUE_STATE_START + i
    }
}

/// Phases of batch computation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum BatchPhase {
    /// Processing individual events (compliance verification)
    Event = 0,
    /// Streaming padded level-0 leaf hashes
    Leaf = 1,
    /// Hashing leaf preimages into leaf hashes
    LeafHash = 2,
    /// Hashing real-event amounts into amount commitments
    CommitmentHash = 3,
    /// Building Merkle tree from event leaves
    Merkle = 4,
    /// Finalizing state root computation
    Finalize = 5,
    /// Padding rows (no constraints active)
    Padding = 6,
}

impl BatchPhase {
    /// Convert to field element
    pub fn to_felt(self) -> Felt {
        ves_stark_primitives::felt_from_u64(self as u64)
    }

    /// Convert from field element
    pub fn from_felt(felt: Felt) -> Option<Self> {
        match felt.as_int() {
            0 => Some(BatchPhase::Event),
            1 => Some(BatchPhase::Leaf),
            2 => Some(BatchPhase::LeafHash),
            3 => Some(BatchPhase::CommitmentHash),
            4 => Some(BatchPhase::Merkle),
            5 => Some(BatchPhase::Finalize),
            6 => Some(BatchPhase::Padding),
            _ => None,
        }
    }
}

/// Compute the padded number of leaves in the event tree.
#[inline]
pub fn padded_leaf_count(num_events: usize) -> usize {
    num_events.max(1).next_power_of_two()
}

/// Compute the number of explicit leaf rows required for a given batch size.
#[inline]
pub fn leaf_row_count(num_events: usize) -> usize {
    padded_leaf_count(num_events)
}

/// Compute the number of amount-commitment hash rows required for a given batch size.
#[inline]
pub fn commitment_hash_row_count(num_events: usize) -> usize {
    num_events * ROWS_PER_COMMITMENT_HASH
}

/// Compute the number of leaf-hash rows required for a given batch size.
#[inline]
pub fn leaf_hash_row_count(num_events: usize) -> usize {
    num_events * ROWS_PER_LEAF_HASH
}

/// Calculate total trace length for a given batch size
pub fn calculate_trace_length(num_events: usize) -> usize {
    // Event processing rows
    let event_rows = num_events * ROWS_PER_EVENT;

    // Leaf rows: one row per padded leaf hash.
    let leaf_rows = leaf_row_count(num_events);

    // Leaf-hash rows: four Rescue permutations per real leaf.
    let leaf_hash_rows = leaf_hash_row_count(num_events);

    // Amount-commitment hash rows: one Rescue segment per real event.
    let commitment_rows = commitment_hash_row_count(num_events);

    // Merkle tree rows: each internal node takes ROWS_PER_MERKLE_NODE rows
    // for in-circuit Rescue hash verification (14 half-rounds + 1 output)
    let merkle_rows = merkle_row_count(num_events);

    // Finalization rows: in-circuit Rescue hash of state root
    let finalize_rows = FINALIZE_ROWS;

    // Total, rounded up to power of 2
    let total =
        event_rows + leaf_rows + leaf_hash_rows + commitment_rows + merkle_rows + finalize_rows;
    total.next_power_of_two().max(MIN_BATCH_TRACE_LENGTH)
}

/// Compute the number of internal Merkle nodes for a given number of events.
///
/// A Merkle tree over `n` leaves has `2^⌈log2(n)⌉ - 1` internal nodes after
/// zero-padding to the next power-of-two leaf count.
#[inline]
pub fn merkle_node_count(num_events: usize) -> usize {
    let padded_leaves = padded_leaf_count(num_events);
    padded_leaves - 1
}

/// Compute total in-circuit Merkle rows required for a given batch size.
#[inline]
pub fn merkle_row_count(num_events: usize) -> usize {
    merkle_node_count(num_events) * ROWS_PER_MERKLE_NODE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_width() {
        assert_eq!(BATCH_TRACE_WIDTH, BASE_TRACE_WIDTH + BATCH_EXTENSION_WIDTH);
        assert!(BATCH_TRACE_WIDTH > BASE_TRACE_WIDTH);
        assert_eq!(batch_cols::RESERVED + 1, BATCH_TRACE_WIDTH);
    }

    #[test]
    fn test_column_indices_non_overlapping() {
        // Verify key column ranges don't overlap
        assert!(batch_cols::BASE_TRACE_END <= batch_cols::EVENT_INDEX);
        assert!(batch_cols::MERKLE_LEFT_END <= batch_cols::MERKLE_RIGHT_START);
        assert!(batch_cols::MERKLE_RIGHT_END <= batch_cols::MERKLE_OUTPUT_START);
        assert!(batch_cols::MERKLE_OUTPUT_END <= batch_cols::MERKLE_LEVEL);
        assert!(batch_cols::PREV_STATE_ROOT_END <= batch_cols::NEW_STATE_ROOT_START);
    }

    #[test]
    fn test_calculate_trace_length() {
        // 8 events: 8*4 + 8 + 8*60 + 8*15 + 7*15 + 15 = 760 -> 1024
        assert_eq!(calculate_trace_length(8), 1024);

        // 16 events: 16*4 + 16 + 16*60 + 16*15 + 15*15 + 15 = 1520 -> 2048
        assert_eq!(calculate_trace_length(16), 2048);

        // 64 events: 64*4 + 64 + 64*60 + 64*15 + 63*15 + 15 = 6080 -> 8192
        assert_eq!(calculate_trace_length(64), 8192);

        // 100 events: 100*4 + 128 + 100*60 + 100*15 + 127*15 + 15 = 9948 -> 16384
        assert_eq!(calculate_trace_length(100), 16384);
    }

    #[test]
    fn test_batch_phase_conversion() {
        for phase in [
            BatchPhase::Event,
            BatchPhase::Leaf,
            BatchPhase::LeafHash,
            BatchPhase::CommitmentHash,
            BatchPhase::Merkle,
            BatchPhase::Finalize,
            BatchPhase::Padding,
        ] {
            let felt = phase.to_felt();
            let recovered = BatchPhase::from_felt(felt);
            assert_eq!(recovered, Some(phase));
        }
    }
}
