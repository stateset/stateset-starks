//! VES STARK - Zero-Knowledge Compliance Proofs for StateSet
//!
//! This crate provides STARK-based zero-knowledge proofs for verifiable
//! compliance in the StateSet ecosystem.
//!
//! # Overview
//!
//! The VES STARK system allows proving compliance with policies (e.g., AML
//! thresholds) without revealing sensitive data. It uses the Winterfell
//! STARK library for proof generation and verification.
//!
//! # Crates
//!
//! - `ves-stark-primitives`: Field arithmetic, hash functions, public inputs
//! - `ves-stark-air`: AIR constraint definitions
//! - `ves-stark-prover`: Proof generation
//! - `ves-stark-verifier`: Proof verification
//!
//! # Example
//!
//! ```no_run
//! use ves_stark_primitives::public_inputs::{CompliancePublicInputs, PolicyParams, compute_policy_hash};
//! use ves_stark_air::policies::aml_threshold::AmlThresholdPolicy;
//! use ves_stark_prover::{ComplianceProver, ComplianceWitness};
//! use ves_stark_verifier::verify_compliance_proof;
//! ```

// Re-export sub-crates
pub use ves_stark_primitives as primitives;
pub use ves_stark_air as air;
pub use ves_stark_prover as prover;
pub use ves_stark_verifier as verifier;
pub use ves_stark_client as client;
