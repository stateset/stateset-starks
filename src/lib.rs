//! VES STARK - Zero-Knowledge Compliance Proofs for StateSet
//!
//! This crate provides STARK-based zero-knowledge proofs for verifiable
//! compliance in the StateSet ecosystem.
//!
//! # Overview
//!
//! The VES STARK system allows proving witness-level compliance with policies
//! (e.g., AML thresholds) without revealing sensitive data. It uses the
//! Winterfell STARK library for proof generation and verification.
//!
//! # Crates
//!
//! - `ves-stark-primitives`: Field arithmetic, hash functions, public inputs
//! - `ves-stark-air`: AIR constraint definitions
//! - `ves-stark-prover`: Proof generation
//! - `ves-stark-verifier`: Proof verification
//! - `ves-stark-client`: Sequencer and Set Chain client helpers
//!
//! The primitives crate also includes canonical commerce intent and
//! authorization receipt hashing for agentic commerce flows.
//!
//! # Example
//!
//! ```no_run
//! use ves_stark_primitives::public_inputs::{CompliancePublicInputs, PolicyParams, compute_policy_hash};
//! use ves_stark_prover::{ComplianceProver, ComplianceWitness, Policy};
//! use ves_stark_verifier::verify_compliance_proof_auto;
//! ```

// Crate-level lints.
//
// `forbid(unsafe_code)` is meaningful here rather than decorative: this crate
// contains no `unsafe`, and the only crate in the workspace that does
// (`ves-stark-zig`, the C FFI surface) is deliberately excluded. `forbid` — not
// `deny` — so it cannot be locally overridden by an `allow` attribute.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

// Re-export sub-crates
pub use ves_stark_air as air;
pub use ves_stark_client as client;
pub use ves_stark_primitives as primitives;
pub use ves_stark_prover as prover;
pub use ves_stark_verifier as verifier;
