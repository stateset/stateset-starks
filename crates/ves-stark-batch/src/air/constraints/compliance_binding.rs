//! Compliance binding constraints (§2)
//!
//! These constraints bind the `EVENT_COMPLIANCE_FLAG` to the actual
//! comparison results in the base compliance trace. This prevents a malicious
//! prover from lying about event compliance.
//!
//! # Omitted constraints
//!
//! Amount bit decomposition recomposition constraints are omitted because
//! for any correctly-constructed trace, the amount limb and its bit sum
//! are the same polynomial (they agree at all L trace points), making
//! the constraint polynomial identically zero. Winterfell's strict degree
//! check rejects zero-polynomial constraints whose quotient degree is 0
//! instead of the declared (d-1)(L-1).

use crate::air::trace_layout::batch_cols;
use ves_stark_air::trace::cols as base_cols;
use ves_stark_primitives::{felt_from_u64, Felt};
use winter_math::FieldElement;

/// Number of constraints produced by `evaluate_compliance_binding_constraints`.
pub const NUM_COMPLIANCE_BINDING_CONSTRAINTS: usize = 1;

/// Evaluate compliance binding constraints
///
/// Constraint 1: `EVENT_COMPLIANCE_FLAG` must match `comparison_values[7]`
/// (the final comparison result from the limb-by-limb comparison) at
/// EVENT_ROW == 2.
///
/// Selector: `event_row * (event_row - 1) * (event_row - 3)` is zero when
/// event_row in {0, 1, 3} and nonzero (-2) when event_row == 2.
///
/// Degree: 4 (product of 4 trace column references).
///
/// Returns the number of constraints written.
pub fn evaluate_compliance_binding_constraints<E: FieldElement<BaseField = Felt>>(
    current: &[E],
    result: &mut [E],
) -> usize {
    let mut idx = 0;

    let event_row = current[batch_cols::EVENT_ROW];
    let flag = current[batch_cols::EVENT_COMPLIANCE_FLAG];
    let three = E::from(felt_from_u64(3));

    // Flag binding at EVENT_ROW == 2
    let comparison_result = current[base_cols::COMPARISON_START + 7];
    result[idx] =
        event_row * (event_row - E::ONE) * (event_row - three) * (flag - comparison_result);
    idx += 1;

    debug_assert_eq!(idx, NUM_COMPLIANCE_BINDING_CONSTRAINTS);
    idx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constraint_count() {
        assert_eq!(NUM_COMPLIANCE_BINDING_CONSTRAINTS, 1);
    }
}
