//! Error types for the VES STARK verifier

use thiserror::Error;

/// Errors that can occur during proof verification
#[derive(Debug, Error)]
pub enum VerifierError {
    /// Invalid proof structure
    #[error("Invalid proof structure: {0}")]
    InvalidProofStructure(String),

    /// Public input mismatch
    #[error("Public input mismatch: {0}")]
    PublicInputMismatch(String),

    /// FRI verification failed
    #[error("FRI verification failed: {0}")]
    FriVerificationFailed(String),

    /// Constraint check failed
    #[error("Constraint check failed: {0}")]
    ConstraintCheckFailed(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    /// Invalid policy hash
    #[error("Invalid policy hash: expected {expected}, got {actual}")]
    InvalidPolicyHash { expected: String, actual: String },

    /// Proof verification failed
    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),
}

impl VerifierError {
    /// Create an invalid proof structure error
    pub fn invalid_structure<S: Into<String>>(msg: S) -> Self {
        Self::InvalidProofStructure(msg.into())
    }

    /// Create a verification failed error
    pub fn verification_failed<S: Into<String>>(msg: S) -> Self {
        Self::VerificationFailed(msg.into())
    }
}
