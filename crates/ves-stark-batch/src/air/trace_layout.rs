//! Extended trace layout for batch proofs
//!
//! The batch trace extends the single-event compliance trace (105 columns)
//! with additional columns for:
//! - Event indexing
//! - Merkle tree computation
//! - State root tracking
//! - Batch metadata

use ves_stark_primitives::Felt;
use ves_stark_air::trace::TRACE_WIDTH as BASE_TRACE_WIDTH;

/// Total width of the batch execution trace
pub const BATCH_TRACE_WIDTH: usize = 160;

/// Minimum trace length for batch proofs
pub const MIN_BATCH_TRACE_LENGTH: usize = 256;

/// Maximum number of events per batch
pub const MAX_BATCH_SIZE: usize = 128;

/// Rows needed per event for compliance verification
pub const ROWS_PER_EVENT: usize = 4;

/// Column indices for the batch trace
pub mod batch_cols {
    use super::BASE_TRACE_WIDTH;

    // =========================================================================
    // Base compliance columns (0-104)
    // These are inherited from the single-event compliance AIR
    // =========================================================================
    pub const BASE_TRACE_END: usize = BASE_TRACE_WIDTH; // 105

    // =========================================================================
    // Event indexing (105-106)
    // =========================================================================
    /// Current event index in the batch (0 to N-1)
    pub const EVENT_INDEX: usize = 105;

    /// Total number of events in batch
    pub const NUM_EVENTS: usize = 106;

    // =========================================================================
    // Merkle tree columns (107-122)
    // Used during Merkle tree construction phase
    // =========================================================================
    /// Merkle left child (4 elements)
    pub const MERKLE_LEFT_START: usize = 107;
    pub const MERKLE_LEFT_END: usize = 111;

    /// Merkle right child (4 elements)
    pub const MERKLE_RIGHT_START: usize = 111;
    pub const MERKLE_RIGHT_END: usize = 115;

    /// Merkle parent/output (4 elements)
    pub const MERKLE_OUTPUT_START: usize = 115;
    pub const MERKLE_OUTPUT_END: usize = 119;

    /// Current Merkle tree level (0 = leaves)
    pub const MERKLE_LEVEL: usize = 119;

    /// Index within current level
    pub const MERKLE_NODE_INDEX: usize = 120;

    /// Flag: is this a Merkle computation row?
    pub const IS_MERKLE_ROW: usize = 121;

    /// Final event tree root (4 elements) - stored after Merkle phase
    pub const EVENT_TREE_ROOT_START: usize = 122;
    pub const EVENT_TREE_ROOT_END: usize = 126;

    // =========================================================================
    // State root columns (126-133)
    // =========================================================================
    /// Previous batch state root (4 elements)
    pub const PREV_STATE_ROOT_START: usize = 126;
    pub const PREV_STATE_ROOT_END: usize = 130;

    /// New batch state root (4 elements)
    pub const NEW_STATE_ROOT_START: usize = 130;
    pub const NEW_STATE_ROOT_END: usize = 134;

    // =========================================================================
    // Compliance accumulator (134-135)
    // =========================================================================
    /// Running AND of all compliance flags
    /// Starts at 1, multiplied by each event's compliance flag
    pub const COMPLIANCE_ACCUMULATOR: usize = 134;

    /// Current event's compliance flag (copied from comparison result)
    pub const EVENT_COMPLIANCE_FLAG: usize = 135;

    // =========================================================================
    // Batch phase and control (136-139)
    // =========================================================================
    /// Current phase (0=event, 1=merkle, 2=finalize)
    pub const BATCH_PHASE: usize = 136;

    /// Row within current event
    pub const EVENT_ROW: usize = 137;

    /// Is this the first row of the trace?
    pub const IS_FIRST_BATCH_ROW: usize = 138;

    /// Is this the last row of the trace?
    pub const IS_LAST_BATCH_ROW: usize = 139;

    // =========================================================================
    // Batch metadata (140-155)
    // =========================================================================
    /// Batch ID (4 elements)
    pub const BATCH_ID_START: usize = 140;
    pub const BATCH_ID_END: usize = 144;

    /// Tenant ID (4 elements)
    pub const TENANT_ID_START: usize = 144;
    pub const TENANT_ID_END: usize = 148;

    /// Store ID (4 elements)
    pub const STORE_ID_START: usize = 148;
    pub const STORE_ID_END: usize = 152;

    /// Sequence start
    pub const SEQUENCE_START: usize = 152;

    /// Sequence end
    pub const SEQUENCE_END: usize = 153;

    /// Timestamp
    pub const TIMESTAMP: usize = 154;

    /// Metadata hash (4 elements)
    pub const METADATA_HASH_START: usize = 155;
    pub const METADATA_HASH_END: usize = 159;

    // =========================================================================
    // Reserved (159)
    // =========================================================================
    pub const RESERVED: usize = 159;

    // =========================================================================
    // Helper functions
    // =========================================================================

    /// Get Merkle left child elements
    #[inline]
    pub fn merkle_left(i: usize) -> usize {
        debug_assert!(i < 4);
        MERKLE_LEFT_START + i
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
}

/// Phases of batch computation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum BatchPhase {
    /// Processing individual events (compliance verification)
    Event = 0,
    /// Building Merkle tree from event leaves
    Merkle = 1,
    /// Finalizing state root computation
    Finalize = 2,
    /// Padding rows (no constraints active)
    Padding = 3,
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
            1 => Some(BatchPhase::Merkle),
            2 => Some(BatchPhase::Finalize),
            3 => Some(BatchPhase::Padding),
            _ => None,
        }
    }
}

/// Calculate total trace length for a given batch size
pub fn calculate_trace_length(num_events: usize) -> usize {
    // Event processing rows
    let event_rows = num_events * ROWS_PER_EVENT;

    // Merkle tree rows: sum of nodes at each level
    // For n leaves (padded to power of 2), need n/2 + n/4 + ... + 1 = n-1 internal nodes
    let padded_leaves = num_events.next_power_of_two();
    let merkle_rows = padded_leaves - 1;

    // Finalization rows
    let finalize_rows = 4;

    // Total, rounded up to power of 2
    let total = event_rows + merkle_rows + finalize_rows;
    total.next_power_of_two().max(MIN_BATCH_TRACE_LENGTH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_width() {
        assert_eq!(BATCH_TRACE_WIDTH, 160);
        assert!(BATCH_TRACE_WIDTH > BASE_TRACE_WIDTH);
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
        // 8 events: 8*4 + 7 + 4 = 43 -> 64
        assert_eq!(calculate_trace_length(8), 256); // min is 256

        // 16 events: 16*4 + 15 + 4 = 83 -> 128 -> 256
        assert_eq!(calculate_trace_length(16), 256);

        // 64 events: 64*4 + 63 + 4 = 323 -> 512
        assert_eq!(calculate_trace_length(64), 512);

        // 100 events: 100*4 + 127 + 4 = 531 -> 1024
        assert_eq!(calculate_trace_length(100), 1024);
    }

    #[test]
    fn test_batch_phase_conversion() {
        for phase in [BatchPhase::Event, BatchPhase::Merkle, BatchPhase::Finalize, BatchPhase::Padding] {
            let felt = phase.to_felt();
            let recovered = BatchPhase::from_felt(felt);
            assert_eq!(recovered, Some(phase));
        }
    }
}
