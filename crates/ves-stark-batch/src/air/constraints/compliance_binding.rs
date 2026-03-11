//! Compliance binding constraints (§2)
//!
//! These constraints bind the `EVENT_COMPLIANCE_FLAG` to the subtraction witness
//! in the event trace. This prevents a malicious
//! prover from lying about event compliance.
//!
//! Event rows are structured as a 4-row segment:
//! - row 0: amount bit decomposition
//! - row 1: subtraction diff decomposition + borrow witness
//! - row 2: flag consumption for the accumulator transition
//! - row 3: segment boundary / accumulator update row
//!
//! The binding enforces:
//! - Amount bit consistency on `EVENT_ROW == 0`
//! - Amount/threshold upper-limb zero checks (u64 convention)
//! - Diff bit consistency and subtraction constraints on `EVENT_ROW == 1`
//! - Final compliance-flag binding on `EVENT_ROW == 2`

use crate::air::trace_layout::batch_cols;
use ves_stark_air::trace::cols as base_cols;
use ves_stark_primitives::{felt_from_u64, Felt};
use winter_math::FieldElement;

/// Number of constraints produced by `evaluate_compliance_binding_constraints`.
pub const NUM_COMPLIANCE_BINDING_CONSTRAINTS: usize = 149;

/// Evaluate compliance binding constraints
///
/// Constraint breakdown:
/// - 64 amount bit binary constraints
/// - 2 amount recomposition constraints
/// - 12 upper-limb zero checks
/// - 64 diff bit binary constraints
/// - 2 diff recomposition constraints
/// - 2 borrow binary constraints
/// - 2 subtraction constraints
/// - 1 final flag binding constraint
///
/// Returns the number of constraints written.
pub fn evaluate_compliance_binding_constraints<E: FieldElement<BaseField = Felt>>(
    current: &[E],
    result: &mut [E],
) -> usize {
    let mut idx = 0;
    let not_done = E::ONE - current[batch_cols::EVENTS_DONE];
    let event_row = current[batch_cols::EVENT_ROW];
    let flag = current[batch_cols::EVENT_COMPLIANCE_FLAG];
    let three = E::from(felt_from_u64(3));
    let two = E::from(felt_from_u64(2));
    let row0 = not_done * (event_row - E::ONE) * (event_row - two) * (event_row - three);
    let row1 = not_done * event_row * (event_row - two) * (event_row - three);
    let row2 = not_done * event_row * (event_row - E::ONE) * (event_row - three);

    // Amount bit binary constraints on EVENT_ROW == 0.
    for i in 0..32 {
        let bit = current[base_cols::AMOUNT_BITS_LIMB0_START + i];
        result[idx] = row0 * bit * (E::ONE - bit);
        idx += 1;
    }
    for i in 0..32 {
        let bit = current[base_cols::AMOUNT_BITS_LIMB1_START + i];
        result[idx] = row0 * bit * (E::ONE - bit);
        idx += 1;
    }

    // Amount recomposition constraints on EVENT_ROW == 0.
    let amount_limb0 = current[base_cols::AMOUNT_START];
    let mut amount_recomp0 = E::ZERO;
    let mut amount_power = E::ONE;
    for i in 0..32 {
        amount_recomp0 += current[base_cols::AMOUNT_BITS_LIMB0_START + i] * amount_power;
        amount_power *= two;
    }
    result[idx] = row0 * (amount_limb0 - amount_recomp0);
    idx += 1;

    let amount_limb1 = current[base_cols::AMOUNT_START + 1];
    let mut amount_recomp1 = E::ZERO;
    amount_power = E::ONE;
    for i in 0..32 {
        amount_recomp1 += current[base_cols::AMOUNT_BITS_LIMB1_START + i] * amount_power;
        amount_power *= two;
    }
    result[idx] = row0 * (amount_limb1 - amount_recomp1);
    idx += 1;

    // u64 convention: amount upper limbs are zero on EVENT_ROW == 0.
    for i in 2..base_cols::NUM_LIMBS {
        result[idx] = row0 * current[base_cols::AMOUNT_START + i];
        idx += 1;
    }

    // The effective-limit upper limbs are zero on EVENT_ROW == 0.
    for i in 2..base_cols::NUM_LIMBS {
        result[idx] = row0 * current[base_cols::THRESHOLD_START + i];
        idx += 1;
    }

    // Diff bit binary constraints on EVENT_ROW == 1.
    for i in 0..32 {
        let bit = current[base_cols::AMOUNT_BITS_LIMB0_START + i];
        result[idx] = row1 * bit * (E::ONE - bit);
        idx += 1;
    }
    for i in 0..32 {
        let bit = current[base_cols::AMOUNT_BITS_LIMB1_START + i];
        result[idx] = row1 * bit * (E::ONE - bit);
        idx += 1;
    }

    // Diff recomposition on EVENT_ROW == 1.
    let diff0 = current[batch_cols::event_diff(0)];
    let mut diff_recomp0 = E::ZERO;
    amount_power = E::ONE;
    for i in 0..32 {
        diff_recomp0 += current[base_cols::AMOUNT_BITS_LIMB0_START + i] * amount_power;
        amount_power *= two;
    }
    result[idx] = row1 * (diff0 - diff_recomp0);
    idx += 1;

    let diff1 = current[batch_cols::event_diff(1)];
    let mut diff_recomp1 = E::ZERO;
    amount_power = E::ONE;
    for i in 0..32 {
        diff_recomp1 += current[base_cols::AMOUNT_BITS_LIMB1_START + i] * amount_power;
        amount_power *= two;
    }
    result[idx] = row1 * (diff1 - diff_recomp1);
    idx += 1;

    // Borrow values are binary on EVENT_ROW == 1.
    let borrow0 = current[batch_cols::event_borrow(0)];
    let borrow1 = current[batch_cols::event_borrow(1)];
    result[idx] = row1 * borrow0 * (E::ONE - borrow0);
    idx += 1;
    result[idx] = row1 * borrow1 * (E::ONE - borrow1);
    idx += 1;

    // Two-limb subtraction witness for amount <= effective_limit on EVENT_ROW == 1.
    let two_pow_32 = E::from(felt_from_u64(1u64 << 32));
    let threshold_low = current[base_cols::THRESHOLD_START];
    let threshold_high = current[base_cols::THRESHOLD_START + 1];
    result[idx] = row1 * (amount_limb0 + diff0 - threshold_low - borrow0 * two_pow_32);
    idx += 1;
    result[idx] = row1 * (amount_limb1 + diff1 + borrow0 - threshold_high - borrow1 * two_pow_32);
    idx += 1;

    // EVENT_ROW == 2 must bind the compliance flag to the final borrow.
    result[idx] = row2 * (flag + borrow1 - E::ONE);
    idx += 1;

    debug_assert_eq!(idx, NUM_COMPLIANCE_BINDING_CONSTRAINTS);
    idx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constraint_count() {
        assert_eq!(NUM_COMPLIANCE_BINDING_CONSTRAINTS, 149);
    }
}
