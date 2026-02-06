//! VES STARK Primitives
//!
//! This crate provides the fundamental cryptographic building blocks for VES compliance proofs:
//! - Field arithmetic using Winterfell's BaseElement (64-bit Goldilocks prime field)
//! - Rescue-Prime hash function (STARK-friendly)
//! - Hash-to-field conversions for 32-byte hashes
//! - Canonical public inputs structures

pub mod field;
pub mod hash;
pub mod public_inputs;
pub mod rescue;

pub use field::{felt_from_u64, felt_to_u64, Felt, FELT_ONE, FELT_ZERO};
pub use hash::{felts_to_hash, hash_to_felts, Hash256};
pub use public_inputs::{
    canonical_json, compute_policy_hash, compute_public_inputs_hash, CompliancePublicInputs,
    PolicyParams, PublicInputsError,
};
pub use rescue::{rescue_hash, rescue_hash_pair, RescueState};
