//! VES STARK AIR (Algebraic Intermediate Representation)
//!
//! This crate defines the constraint systems for VES compliance proofs.
//! Phase 1 implements per-event compliance proofs, starting with the
//! `aml.threshold` policy.
//!
//! # Architecture
//!
//! The AIR is structured as:
//! - `compliance`: Main compliance AIR that orchestrates sub-AIRs
//! - `policies/aml_threshold`: AML threshold policy constraints
//! - `policies/order_total_cap`: Order total cap policy constraints
//! - `rescue_air`: Rescue-Prime hash constraints (for public input binding)
//! - `range_check`: Range proof constraints for u32 limbs
//! - `trace`: Trace layout and column definitions

pub mod compliance;
pub mod policies;
pub mod range_check;
pub mod rescue_air;
pub mod trace;
pub mod options;

pub use compliance::ComplianceAir;
pub use options::ProofOptions;
pub use range_check::{validate_limbs, is_valid_u32};
pub use trace::{TraceInfo, TRACE_WIDTH};
