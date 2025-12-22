//! VES STARK Primitives
//!
//! This crate provides the fundamental cryptographic building blocks for VES compliance proofs:
//! - Field arithmetic using Winterfell's BaseElement (64-bit Goldilocks prime field)
//! - Rescue-Prime hash function (STARK-friendly)
//! - Hash-to-field conversions for 32-byte hashes
//! - Canonical public inputs structures

pub mod field;
pub mod rescue;
pub mod hash;
pub mod public_inputs;

pub use field::{Felt, felt_from_u64, felt_to_u64, FELT_ZERO, FELT_ONE};
pub use rescue::{rescue_hash, rescue_hash_pair, RescueState};
pub use hash::{hash_to_felts, felts_to_hash, Hash256};
pub use public_inputs::{
    CompliancePublicInputs, PolicyParams, compute_policy_hash,
    compute_public_inputs_hash, canonical_json,
};
