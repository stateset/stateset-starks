//! Error types for the VES STARK prover

use thiserror::Error;

/// Errors that can occur during proof generation
#[derive(Debug, Error)]
pub enum ProverError {
    /// Invalid witness data
    #[error("Invalid witness: {0}")]
    InvalidWitness(String),

    /// Constraint violation detected
    #[error("Constraint violation: {0}")]
    ConstraintViolation(String),

    /// Policy validation failed
    #[error("Policy validation failed: {0}")]
    PolicyValidationFailed(String),

    /// Trace generation error
    #[error("Trace generation error: {0}")]
    TraceGenerationError(String),

    /// Proof generation failed
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Invalid public inputs
    #[error("Invalid public inputs: {0}")]
    InvalidPublicInputs(String),
}

impl ProverError {
    /// Create an invalid witness error
    pub fn invalid_witness<S: Into<String>>(msg: S) -> Self {
        Self::InvalidWitness(msg.into())
    }

    /// Create a constraint violation error
    pub fn constraint_violation<S: Into<String>>(msg: S) -> Self {
        Self::ConstraintViolation(msg.into())
    }

    /// Create a policy validation error
    pub fn policy_validation_failed<S: Into<String>>(msg: S) -> Self {
        Self::PolicyValidationFailed(msg.into())
    }
}
