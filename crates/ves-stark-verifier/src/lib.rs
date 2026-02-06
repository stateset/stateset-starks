//! VES STARK Verifier
//!
//! This crate provides STARK proof verification for VES compliance proofs.
//! The verifier is stateless and can verify proofs using only the proof
//! bytes and public inputs.
//!
//! # Usage
//!
//! ```ignore
//! use ves_stark_verifier::verify_compliance_proof_auto;
//!
//! let result = verify_compliance_proof_auto(&proof_bytes, &public_inputs, &witness_commitment)?;
//! assert!(result.valid);
//! ```

mod error;
mod verify;

pub use error::{validate_hex_string, VerifierError, PROOF_VERSION};
pub use verify::{
    verify_compliance_proof, verify_compliance_proof_auto, ComplianceVerifier, VerificationResult,
};
