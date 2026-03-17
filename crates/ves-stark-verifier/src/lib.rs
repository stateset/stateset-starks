//! VES STARK Verifier
//!
//! This crate provides STARK proof verification for VES compliance proofs.
//! The verifier is stateless and can verify proofs using only the proof
//! bytes and public inputs.
//!
//! # Usage
//!
//! ```ignore
//! use ves_stark_verifier::verify_compliance_proof_auto_with_amount_binding_strict;
//!
//! // Requires a canonical payload amount binding artifact for strict verification.
//! let result =
//!     verify_compliance_proof_auto_with_amount_binding_strict(&proof_bytes, &public_inputs, &binding)?;
//! assert!(result.valid);
//! ```

mod error;
mod verify;

pub use error::{validate_hex_string, VerifierError, MAX_PROOF_SIZE, PROOF_VERSION};
pub use verify::{
    verify_agent_authorization_proof, verify_agent_authorization_proof_auto,
    verify_agent_authorization_proof_auto_bound,
    verify_agent_authorization_proof_auto_bound_strict,
    verify_agent_authorization_proof_auto_bound_witness_strict,
    verify_agent_authorization_proof_auto_strict,
    verify_agent_authorization_proof_auto_with_amount_binding,
    verify_agent_authorization_proof_auto_with_amount_binding_strict,
    verify_agent_authorization_proof_auto_witness_strict, verify_agent_authorization_proof_strict,
    verify_agent_authorization_proof_with_amount_binding,
    verify_agent_authorization_proof_with_amount_binding_strict,
    verify_agent_authorization_proof_witness_strict, verify_compliance_proof,
    verify_compliance_proof_auto, verify_compliance_proof_auto_bound,
    verify_compliance_proof_auto_bound_strict, verify_compliance_proof_auto_bound_witness_strict,
    verify_compliance_proof_auto_strict, verify_compliance_proof_auto_with_amount_binding,
    verify_compliance_proof_auto_with_amount_binding_strict,
    verify_compliance_proof_auto_witness_strict, verify_compliance_proof_strict,
    verify_compliance_proof_with_amount_binding,
    verify_compliance_proof_with_amount_binding_strict, verify_compliance_proof_witness_strict,
    ComplianceVerifier, VerificationResult,
};
