//! Constraint modules for batch AIR

pub mod accumulator;
pub mod compliance_binding;
pub mod event;
pub mod merkle;
pub mod state_transition;

// Active constraints used by BatchComplianceAir:
pub use compliance_binding::{
    evaluate_compliance_binding_constraints, NUM_COMPLIANCE_BINDING_CONSTRAINTS,
};
pub use merkle::{
    evaluate_merkle_constraints,
    PERIODIC_COLUMN_COUNT,
    PERIODIC_RESCUE_ACTIVE_IDX,
    PERIODIC_RESCUE_CONST_START_IDX,
    PERIODIC_RESCUE_INIT_IDX,
    PERIODIC_RESCUE_IS_FORWARD_IDX,
    NUM_MERKLE_CONSTRAINTS,
};

// Reference implementations retained for Phase 3+ development.
// These are NOT called by the current AIR; see each module's doc comment.
pub use accumulator::evaluate_accumulator_constraints;
pub use event::evaluate_event_constraints;
pub use state_transition::evaluate_state_transition_constraints;
