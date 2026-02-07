//! VES STARK Verifier
//!
//! This crate provides STARK proof verification for VES compliance proofs.
//! The verifier is stateless and can verify proofs using only the proof
//! bytes and public inputs.
//!
//! # Usage
//!
//! ```ignore
//! use ves_stark_verifier::verify_compliance_proof_auto_bound;
//!
//! // Requires `public_inputs.witnessCommitment` to be present.
//! let result = verify_compliance_proof_auto_bound(&proof_bytes, &public_inputs)?;
//! assert!(result.valid);
//! ```

mod error;
mod verify;

pub use error::{validate_hex_string, VerifierError, PROOF_VERSION};
pub use verify::{
    verify_compliance_proof, verify_compliance_proof_auto, verify_compliance_proof_auto_bound,
    ComplianceVerifier, VerificationResult,
};
