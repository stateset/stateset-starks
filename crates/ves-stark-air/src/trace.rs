//! Execution Trace Layout for VES Compliance AIR
//!
//! The trace is organized to prove:
//! 1. Public inputs are bound to the trace via boundary assertions (row 0)
//! 2. A private `amount` value satisfies the selected policy inequality
//! 3. The witness amount is bound to the proof via an in-AIR Rescue commitment
//! 4. Range validity for u32 limbs via bit decomposition (limbs 0-1 only; limbs 2-7 are
//!    boundary-asserted to 0 to represent a u64)
//!
//! For the `aml.threshold` policy, the AIR enforces `amount < threshold` by proving
//! `amount <= threshold - 1` (effective limit) via a 2-limb (u64) subtraction gadget.
//!
//! Note: Public inputs include payload hashes and event metadata, but the current AIR does **not**
//! algebraically link those hashes to the private amount. That linkage is handled by the
//! surrounding protocol/pipeline, not by this AIR.

use ves_stark_primitives::Felt;

/// Total width of the execution trace (number of columns)
///
/// Layout (current):
/// - Columns 0-11: Rescue state (12 elements for permutation)
/// - Columns 12-19: Witness data (amount as 8 u32 limbs; only limbs 0-1 are range-checked)
/// - Columns 20-27: Threshold data (8 u32 limbs)
/// - Columns 28-35: Legacy comparison flags / intermediates (unused by current AIR)
/// - Columns 36-39: Control flags (is_first, is_last, round_counter, phase)
/// - Columns 40-71: Amount limb 0 bit decomposition (32 bits)
/// - Columns 72-103: Amount limb 1 bit decomposition (32 bits)
/// - Column 104: Legacy commitment flag (unused by current AIR)
/// - Columns 105-112: diff[i] (subtraction witness; limbs 2-7 are asserted to 0)
/// - Columns 113-120: borrow[i] (subtraction witness; limbs 2-7 are unused)
/// - Columns 121-128: Legacy is_less[i] (unused by current AIR)
/// - Columns 129-136: Legacy is_equal[i] (unused by current AIR)
///
/// Note: Limbs 2-7 are boundary-asserted to zero (for u64 amounts), so no binary
/// decomposition is needed. The value 0 is trivially a valid u32.
/// Winterfell has a 255-column limit, so we stay within that bound.
pub const TRACE_WIDTH: usize = 248;

/// Legacy trace width for backward compatibility
pub const TRACE_WIDTH_LEGACY: usize = 40;

/// Number of rows in the trace (power of 2)
/// For Phase 1 compliance proofs, we use a small trace:
/// - 128 rows for Rescue permutation + comparison logic
pub const MIN_TRACE_LENGTH: usize = 128;

/// Column indices for the trace
pub mod cols {
    // Rescue state columns (0-11)
    pub const RESCUE_STATE_START: usize = 0;
    pub const RESCUE_STATE_END: usize = 12;

    // Witness amount columns (12-19) - 8 x u32 limbs
    pub const AMOUNT_START: usize = 12;
    pub const AMOUNT_END: usize = 20;

    // Threshold columns (20-27) - 8 x u32 limbs
    pub const THRESHOLD_START: usize = 20;
    pub const THRESHOLD_END: usize = 28;

    // Comparison intermediate values (28-35)
    // These hold the limb-by-limb comparison results
    pub const COMPARISON_START: usize = 28;
    pub const COMPARISON_END: usize = 36;

    // Control flags (36-39)
    pub const FLAG_IS_FIRST: usize = 36;
    pub const FLAG_IS_LAST: usize = 37;
    pub const ROUND_COUNTER: usize = 38;
    pub const PHASE: usize = 39;

    // Binary decomposition columns for range proofs
    // Amount limb 0 bits (40-71) - 32 bits for low u32
    pub const AMOUNT_BITS_LIMB0_START: usize = 40;
    pub const AMOUNT_BITS_LIMB0_END: usize = 72;

    // Amount limb 1 bits (72-103) - 32 bits for high u32
    pub const AMOUNT_BITS_LIMB1_START: usize = 72;
    pub const AMOUNT_BITS_LIMB1_END: usize = 104;

    // Rescue hash commitment flag (104)
    pub const RESCUE_COMMIT_FLAG: usize = 104;

    // =========================================================================
    // Legacy Columns: Comparison Gadget (unused by current AIR)
    // =========================================================================

    // diff[i] = threshold[i] - amount[i] - 1 when amount[i] < threshold[i] (105-112)
    pub const DIFF_START: usize = 105;
    pub const DIFF_END: usize = 113;

    // borrow[i] = 1 if amount[i] > threshold[i] at position i (113-120)
    pub const BORROW_START: usize = 113;
    pub const BORROW_END: usize = 121;

    // is_less[i] = 1 if determined amount < threshold considering limbs [i..7] (121-128)
    pub const IS_LESS_START: usize = 121;
    pub const IS_LESS_END: usize = 129;

    // is_equal[i] = 1 if all limbs [i..7] are equal (129-136)
    pub const IS_EQUAL_START: usize = 129;
    pub const IS_EQUAL_END: usize = 137;

    // =========================================================================
    // Diff Bit Decomposition (u32 for limbs 0-1)
    // =========================================================================

    // diff limb 0 bits (137-168)
    pub const DIFF_BITS_LIMB0_START: usize = 137;
    pub const DIFF_BITS_LIMB0_END: usize = 169;

    // diff limb 1 bits (169-200)
    pub const DIFF_BITS_LIMB1_START: usize = 169;
    pub const DIFF_BITS_LIMB1_END: usize = 201;

    // Public inputs binding columns (201-247)
    pub const PUBLIC_INPUTS_START: usize = 201;
    pub const PUBLIC_INPUTS_END: usize = 248;
    pub const PUBLIC_INPUTS_LEN: usize = PUBLIC_INPUTS_END - PUBLIC_INPUTS_START;

    /// Number of bits per limb
    pub const BITS_PER_LIMB: usize = 32;

    /// Number of limbs
    pub const NUM_LIMBS: usize = 8;

    /// Get bit column start index for limbs 0-1 (only these have binary decomposition)
    /// Limbs 2-7 are boundary-asserted to zero and don't need binary decomposition
    #[inline]
    pub const fn amount_limb_bits_start(limb_idx: usize) -> usize {
        match limb_idx {
            0 => AMOUNT_BITS_LIMB0_START,
            1 => AMOUNT_BITS_LIMB1_START,
            // Limbs 2-7 don't have bit decomposition columns
            // They are boundary-asserted to zero
            _ => panic!("Only limbs 0-1 have binary decomposition"),
        }
    }

    /// Get bit column index for limb 0
    #[inline]
    pub fn amount_limb0_bit(bit_idx: usize) -> usize {
        debug_assert!(bit_idx < BITS_PER_LIMB);
        AMOUNT_BITS_LIMB0_START + bit_idx
    }

    /// Get bit column index for limb 1
    #[inline]
    pub fn amount_limb1_bit(bit_idx: usize) -> usize {
        debug_assert!(bit_idx < BITS_PER_LIMB);
        AMOUNT_BITS_LIMB1_START + bit_idx
    }

    /// Get bit column index for limbs 0-1 only
    #[inline]
    pub fn amount_limb_bit(limb_idx: usize, bit_idx: usize) -> usize {
        debug_assert!(limb_idx < 2, "Only limbs 0-1 have binary decomposition");
        debug_assert!(bit_idx < BITS_PER_LIMB);
        amount_limb_bits_start(limb_idx) + bit_idx
    }

    /// Get diff bit column index for limb 0
    #[inline]
    pub fn diff_limb0_bit(bit_idx: usize) -> usize {
        debug_assert!(bit_idx < BITS_PER_LIMB);
        DIFF_BITS_LIMB0_START + bit_idx
    }

    /// Get diff bit column index for limb 1
    #[inline]
    pub fn diff_limb1_bit(bit_idx: usize) -> usize {
        debug_assert!(bit_idx < BITS_PER_LIMB);
        DIFF_BITS_LIMB1_START + bit_idx
    }

    /// Get diff bit column index for limbs 0-1 only
    #[inline]
    pub fn diff_limb_bit(limb_idx: usize, bit_idx: usize) -> usize {
        debug_assert!(limb_idx < 2, "Only limbs 0-1 have diff bit decomposition");
        debug_assert!(bit_idx < BITS_PER_LIMB);
        match limb_idx {
            0 => diff_limb0_bit(bit_idx),
            1 => diff_limb1_bit(bit_idx),
            _ => unreachable!("Only limbs 0-1 have diff bit decomposition"),
        }
    }

    /// Get diff column index
    #[inline]
    pub fn diff(limb_idx: usize) -> usize {
        debug_assert!(limb_idx < NUM_LIMBS);
        DIFF_START + limb_idx
    }

    /// Get borrow column index
    #[inline]
    pub fn borrow(limb_idx: usize) -> usize {
        debug_assert!(limb_idx < NUM_LIMBS);
        BORROW_START + limb_idx
    }

    /// Get is_less column index
    #[inline]
    pub fn is_less(limb_idx: usize) -> usize {
        debug_assert!(limb_idx < NUM_LIMBS);
        IS_LESS_START + limb_idx
    }

    /// Get is_equal column index
    #[inline]
    pub fn is_equal(limb_idx: usize) -> usize {
        debug_assert!(limb_idx < NUM_LIMBS);
        IS_EQUAL_START + limb_idx
    }

    /// Get public input column index
    #[inline]
    pub fn public_input(idx: usize) -> usize {
        debug_assert!(idx < PUBLIC_INPUTS_LEN);
        PUBLIC_INPUTS_START + idx
    }
}

/// Phases of the computation
pub mod phases {
    /// Rescue hash computation phase
    pub const RESCUE_HASH: u64 = 0;
    /// Amount comparison phase
    pub const COMPARISON: u64 = 1;
    /// Padding phase (no constraints)
    pub const PADDING: u64 = 2;
}

/// Trace information for the AIR
#[derive(Debug, Clone)]
pub struct TraceInfo {
    /// Length of the trace (must be power of 2)
    pub length: usize,
    /// Width of the trace
    pub width: usize,
}

impl TraceInfo {
    /// Create new trace info with the given length
    pub fn new(length: usize) -> Self {
        // Round up to power of 2
        let length = length.next_power_of_two().max(MIN_TRACE_LENGTH);
        Self {
            length,
            width: TRACE_WIDTH,
        }
    }
}

/// A row of the execution trace
#[derive(Debug, Clone)]
pub struct TraceRow {
    pub values: [Felt; TRACE_WIDTH],
}

impl TraceRow {
    /// Create a zero row
    pub fn zero() -> Self {
        Self {
            values: [ves_stark_primitives::FELT_ZERO; TRACE_WIDTH],
        }
    }

    /// Get bit decomposition for amount limb 0
    pub fn amount_limb0_bits(&self) -> [Felt; 32] {
        let mut bits = [ves_stark_primitives::FELT_ZERO; 32];
        bits.copy_from_slice(
            &self.values[cols::AMOUNT_BITS_LIMB0_START..cols::AMOUNT_BITS_LIMB0_END],
        );
        bits
    }

    /// Set bit decomposition for amount limb 0
    pub fn set_amount_limb0_bits(&mut self, bits: &[Felt; 32]) {
        self.values[cols::AMOUNT_BITS_LIMB0_START..cols::AMOUNT_BITS_LIMB0_END]
            .copy_from_slice(bits);
    }

    /// Get bit decomposition for amount limb 1
    pub fn amount_limb1_bits(&self) -> [Felt; 32] {
        let mut bits = [ves_stark_primitives::FELT_ZERO; 32];
        bits.copy_from_slice(
            &self.values[cols::AMOUNT_BITS_LIMB1_START..cols::AMOUNT_BITS_LIMB1_END],
        );
        bits
    }

    /// Set bit decomposition for amount limb 1
    pub fn set_amount_limb1_bits(&mut self, bits: &[Felt; 32]) {
        self.values[cols::AMOUNT_BITS_LIMB1_START..cols::AMOUNT_BITS_LIMB1_END]
            .copy_from_slice(bits);
    }

    /// Get rescue commit flag
    pub fn rescue_commit_flag(&self) -> Felt {
        self.values[cols::RESCUE_COMMIT_FLAG]
    }

    /// Set rescue commit flag
    pub fn set_rescue_commit_flag(&mut self, value: Felt) {
        self.values[cols::RESCUE_COMMIT_FLAG] = value;
    }

    /// Get rescue state from this row
    pub fn rescue_state(&self) -> [Felt; 12] {
        let mut state = [ves_stark_primitives::FELT_ZERO; 12];
        state.copy_from_slice(&self.values[cols::RESCUE_STATE_START..cols::RESCUE_STATE_END]);
        state
    }

    /// Set rescue state in this row
    pub fn set_rescue_state(&mut self, state: &[Felt; 12]) {
        self.values[cols::RESCUE_STATE_START..cols::RESCUE_STATE_END].copy_from_slice(state);
    }

    /// Get amount limbs from this row
    pub fn amount_limbs(&self) -> [Felt; 8] {
        let mut limbs = [ves_stark_primitives::FELT_ZERO; 8];
        limbs.copy_from_slice(&self.values[cols::AMOUNT_START..cols::AMOUNT_END]);
        limbs
    }

    /// Set amount limbs in this row
    pub fn set_amount_limbs(&mut self, limbs: &[Felt; 8]) {
        self.values[cols::AMOUNT_START..cols::AMOUNT_END].copy_from_slice(limbs);
    }

    /// Get threshold limbs from this row
    pub fn threshold_limbs(&self) -> [Felt; 8] {
        let mut limbs = [ves_stark_primitives::FELT_ZERO; 8];
        limbs.copy_from_slice(&self.values[cols::THRESHOLD_START..cols::THRESHOLD_END]);
        limbs
    }

    /// Set threshold limbs in this row
    pub fn set_threshold_limbs(&mut self, limbs: &[Felt; 8]) {
        self.values[cols::THRESHOLD_START..cols::THRESHOLD_END].copy_from_slice(limbs);
    }

    /// Get comparison values from this row
    pub fn comparison_values(&self) -> [Felt; 8] {
        let mut values = [ves_stark_primitives::FELT_ZERO; 8];
        values.copy_from_slice(&self.values[cols::COMPARISON_START..cols::COMPARISON_END]);
        values
    }

    /// Set comparison values in this row
    pub fn set_comparison_values(&mut self, values: &[Felt; 8]) {
        self.values[cols::COMPARISON_START..cols::COMPARISON_END].copy_from_slice(values);
    }

    /// Get control flags
    pub fn is_first(&self) -> Felt {
        self.values[cols::FLAG_IS_FIRST]
    }

    pub fn is_last(&self) -> Felt {
        self.values[cols::FLAG_IS_LAST]
    }

    pub fn round_counter(&self) -> Felt {
        self.values[cols::ROUND_COUNTER]
    }

    pub fn phase(&self) -> Felt {
        self.values[cols::PHASE]
    }

    /// Set control flags
    pub fn set_is_first(&mut self, value: Felt) {
        self.values[cols::FLAG_IS_FIRST] = value;
    }

    pub fn set_is_last(&mut self, value: Felt) {
        self.values[cols::FLAG_IS_LAST] = value;
    }

    pub fn set_round_counter(&mut self, value: Felt) {
        self.values[cols::ROUND_COUNTER] = value;
    }

    pub fn set_phase(&mut self, value: Felt) {
        self.values[cols::PHASE] = value;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_info_power_of_two() {
        let info = TraceInfo::new(100);
        assert_eq!(info.length, MIN_TRACE_LENGTH); // 128 is the minimum

        let info = TraceInfo::new(200);
        assert_eq!(info.length, 256);
    }

    #[test]
    fn test_trace_row_accessors() {
        let mut row = TraceRow::zero();

        let state = [ves_stark_primitives::felt_from_u64(1); 12];
        row.set_rescue_state(&state);
        assert_eq!(row.rescue_state(), state);

        let limbs = [ves_stark_primitives::felt_from_u64(2); 8];
        row.set_amount_limbs(&limbs);
        assert_eq!(row.amount_limbs(), limbs);
    }
}
