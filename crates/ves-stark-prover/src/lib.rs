//! VES STARK Prover
//!
//! This crate provides STARK proof generation for VES compliance proofs.
//! It handles:
//! - Witness generation from VES event data
//! - Execution trace construction
//! - STARK proof generation using Winterfell
//!
//! # Multi-Policy Support
//!
//! The prover supports multiple policy types:
//! - `aml.threshold`: Proves amount < threshold (strict less-than)
//! - `order_total.cap`: Proves amount <= cap (less-than-or-equal)
//!
//! # Usage
//!
//! ```ignore
//! use ves_stark_prover::{ComplianceProver, ComplianceWitness, Policy};
//!
//! // Create witness
//! let witness = ComplianceWitness::new(amount, public_inputs);
//!
//! // Create prover with AML threshold policy
//! let prover = ComplianceProver::with_policy(Policy::aml_threshold(10000));
//! let proof = prover.prove(&witness)?;
//!
//! // Or with order total cap policy
//! let prover = ComplianceProver::with_policy(Policy::order_total_cap(50000));
//! let proof = prover.prove(&witness)?;
//! ```

pub mod error;
pub mod policy;
pub mod prover;
pub mod serialization;
pub mod trace;
pub mod witness;

pub use error::ProverError;
pub use policy::{ComparisonType, Policy, PolicyError};
pub use prover::{ComplianceProof, ComplianceProver, ProofMetadata};
pub use serialization::{
    deserialize_proof_bytes, deserialize_proof_bytes_auto, serialize_proof,
    serialize_proof_with_policy, CompactProof, PolicyInfo, ProofFormat, ProofJson,
};
pub use witness::ComplianceWitness;
