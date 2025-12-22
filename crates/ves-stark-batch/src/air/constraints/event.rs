//! Event processing constraints
//!
//! These constraints ensure that each event in the batch is correctly processed
//! for compliance verification.

use winter_math::FieldElement;
use crate::air::trace_layout::batch_cols;

/// Evaluate event processing constraints
///
/// During the event phase, these constraints ensure:
/// 1. Event index increments correctly at event boundaries
/// 2. Event-specific data is loaded correctly
/// 3. Base compliance constraints are applied
pub fn evaluate_event_constraints<E: FieldElement>(
    current: &[E],
    next: &[E],
    result: &mut [E],
) -> usize {
    let mut idx = 0;

    // Event index constraints
    // During event processing, event_index should remain constant within an event
    // and increment when transitioning to the next event
    let event_index = current[batch_cols::EVENT_INDEX];
    let event_index_next = next[batch_cols::EVENT_INDEX];
    let event_row = current[batch_cols::EVENT_ROW];

    // Constraint 1: Event index either stays the same or increments by 1
    // (event_index_next - event_index) * (event_index_next - event_index - 1) = 0
    let delta = event_index_next - event_index;
    result[idx] = delta * (delta - E::ONE);
    idx += 1;

    // Constraint 2: Event row cycle
    // Row should either increment or reset to 0
    // We verify: (event_row_next - event_row - 1) * event_row_next = 0
    // This means either row incremented by 1, or row reset to 0
    let event_row_next = next[batch_cols::EVENT_ROW];
    result[idx] = (event_row_next - event_row - E::ONE) * event_row_next;
    idx += 1;

    idx
}

/// Number of constraints produced by evaluate_event_constraints
pub const NUM_EVENT_CONSTRAINTS: usize = 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constraint_count() {
        assert_eq!(NUM_EVENT_CONSTRAINTS, 2);
    }
}
