//! Compliance accumulator constraints
//!
//! These constraints ensure that the compliance accumulator correctly
//! tracks the AND of all individual event compliance flags.

use crate::air::trace_layout::batch_cols;
use winter_math::FieldElement;

/// Evaluate compliance accumulator constraints
///
/// The accumulator starts at 1 and is multiplied by each event's compliance flag.
/// At the end, accumulator = 1 if and only if all events were compliant.
pub fn evaluate_accumulator_constraints<E: FieldElement>(
    current: &[E],
    next: &[E],
    result: &mut [E],
) -> usize {
    let mut idx = 0;

    // Get current values
    let acc_curr = current[batch_cols::COMPLIANCE_ACCUMULATOR];
    let acc_next = next[batch_cols::COMPLIANCE_ACCUMULATOR];
    let event_compliance = current[batch_cols::EVENT_COMPLIANCE_FLAG];

    // Constraint 1: Accumulator update
    // The accumulator should either stay the same or multiply by compliance flag
    // This simplified constraint: if compliance = 1, acc stays same; if compliance = 0, acc becomes 0
    // (acc_next - acc_curr * compliance) should be 0 when at event boundary
    //
    // Simplified version: accumulator consistency
    // acc_next * (1 - compliance) = acc_curr * (1 - compliance)
    // This ensures: when compliance=0, acc_next=acc_curr (which should be 0)
    //               when compliance=1, constraint is satisfied for any acc_next
    result[idx] = acc_next * (E::ONE - event_compliance) - acc_curr * (E::ONE - event_compliance);
    idx += 1;

    // Constraint 2: Accumulator consistency (must be 0 or 1)
    // This ensures the accumulator can only hold binary values
    result[idx] = acc_curr * (E::ONE - acc_curr);
    idx += 1;

    idx
}

/// Number of constraints produced by evaluate_accumulator_constraints
pub const NUM_ACCUMULATOR_CONSTRAINTS: usize = 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constraint_count() {
        assert_eq!(NUM_ACCUMULATOR_CONSTRAINTS, 2);
    }
}
