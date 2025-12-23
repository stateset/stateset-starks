//! VES STARK Verifier
//!
//! This crate provides STARK proof verification for VES compliance proofs.
//! The verifier is stateless and can verify proofs using only the proof
//! bytes and public inputs.
//!
//! # Usage
//!
//! ```ignore
//! use ves_stark_verifier::{verify_compliance_proof, VerificationResult};
//!
//! let result = verify_compliance_proof(&proof_bytes, &public_inputs)?;
//! assert!(result.valid);
//! ```

mod error;
mod verify;

pub use error::{VerifierError, PROOF_VERSION, validate_hex_string};
pub use verify::{
    verify_compliance_proof,
    VerificationResult,
    ComplianceVerifier,
};
