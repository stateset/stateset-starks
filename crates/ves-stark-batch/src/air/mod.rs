//! Batch AIR (Algebraic Intermediate Representation)
//!
//! This module defines the AIR for batch state transition proofs.

pub mod batch_air;
pub mod constraints;
pub mod trace_layout;

pub use batch_air::BatchComplianceAir;
pub use trace_layout::{batch_cols, BatchPhase, BATCH_TRACE_WIDTH};
