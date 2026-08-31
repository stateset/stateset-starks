//! VES STARK Primitives
//!
//! This crate provides the fundamental cryptographic building blocks for VES compliance proofs:
//! - Field arithmetic using Winterfell's BaseElement (64-bit Goldilocks prime field)
//! - Rescue-Prime hash function (STARK-friendly)
//! - Hash-to-field conversions for 32-byte hashes
//! - Canonical public inputs structures

// Crate-level lints.
//
// `forbid(unsafe_code)` is meaningful here rather than decorative: this crate
// contains no `unsafe`, and the only crate in the workspace that does
// (`ves-stark-zig`, the C FFI surface) is deliberately excluded. `forbid` — not
// `deny` — so it cannot be locally overridden by an `allow` attribute.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod bounded_reader;
pub mod commerce_intent;
pub mod field;
pub mod hash;
pub mod panic_guard;
pub mod payload_amount;
pub mod payload_v2;
pub mod public_inputs;
pub mod rescue;

pub use commerce_intent::{
    CommerceAuthorizationReceipt, CommerceExecution, CommerceIntent, CommerceIntentError,
    DOMAIN_COMMERCE_AUTHORIZATION_RECEIPT_HASH, DOMAIN_COMMERCE_INTENT_HASH,
};
pub use field::{felt_from_u64, felt_to_u64, Felt, FELT_ONE, FELT_ZERO};
pub use hash::{
    felts_to_hash, hash_to_felts, Hash256, BATCH_PROOF_HASH_DOMAIN, COMPLIANCE_PROOF_HASH_DOMAIN,
};
pub use payload_amount::{
    amount_field_candidates, amount_witness_commitment, extract_payload_amount,
    AmountExtractionError,
};
pub use public_inputs::{
    canonical_json, compute_bound_public_inputs_hash, compute_full_public_inputs_hash,
    compute_policy_hash, compute_public_inputs_hash, witness_commitment_hex_to_u64,
    witness_commitment_u64_to_hex, CompliancePublicInputs, PayloadAmountBinding, PolicyParams,
    PublicInputsError, DOMAIN_PAYLOAD_AMOUNT_BINDING_HASH,
};
pub use rescue::{rescue_hash, rescue_hash_pair, RescueState};
