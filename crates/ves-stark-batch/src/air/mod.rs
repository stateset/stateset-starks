//! Batch AIR (Algebraic Intermediate Representation)
//!
//! This module defines the AIR for batch state transition proofs.

pub mod trace_layout;
pub mod batch_air;
pub mod constraints;

pub use trace_layout::{BATCH_TRACE_WIDTH, batch_cols, BatchPhase};
pub use batch_air::BatchComplianceAir;
