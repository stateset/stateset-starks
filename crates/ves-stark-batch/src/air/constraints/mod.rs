//! Constraint modules for batch AIR
//!
//! The batch AIR uses a simplified constraint system that validates:
//! - State root consistency (constant throughout trace)
//! - Compliance accumulator updates
//! - Metadata consistency
//! - Phase validity

pub mod event;
pub mod merkle;
pub mod state_transition;
pub mod accumulator;

// Note: These functions are available for future use when adding
// more rigorous constraint checking

pub use event::evaluate_event_constraints;
pub use merkle::evaluate_merkle_constraints;
pub use state_transition::evaluate_state_transition_constraints;
pub use accumulator::evaluate_accumulator_constraints;

// The simplified batch AIR uses only 32 constraints
// This can be extended later for more rigorous verification
