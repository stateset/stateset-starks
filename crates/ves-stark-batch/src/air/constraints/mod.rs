//! Constraint modules for batch AIR
//!
//! The batch AIR uses a simplified constraint system that validates:
//! - State root consistency (constant throughout trace)
//! - Compliance accumulator updates
//! - Metadata consistency
//! - Phase validity

pub mod accumulator;
pub mod event;
pub mod merkle;
pub mod state_transition;

// Note: These functions are available for future use when adding
// more rigorous constraint checking

pub use accumulator::evaluate_accumulator_constraints;
pub use event::evaluate_event_constraints;
pub use merkle::evaluate_merkle_constraints;
pub use state_transition::evaluate_state_transition_constraints;

// The simplified batch AIR uses only 32 constraints
// This can be extended later for more rigorous verification
