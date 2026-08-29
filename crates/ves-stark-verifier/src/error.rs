//! Error types for the VES STARK verifier

use thiserror::Error;

/// Current proof version (internal; used for compatibility checks where applicable)
pub const PROOF_VERSION: u32 = 2;

/// Maximum allowed proof size in bytes (10 MB)
pub const MAX_PROOF_SIZE: usize = 10 * 1024 * 1024;

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
    InvalidPolicyHash {
        /// Policy hash recomputed from the verifier's own policy.
        expected: String,
        /// Policy hash carried in the proof's public inputs.
        actual: String,
    },

    /// Proof verification failed
    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),

    // V2 Security Hardening - New Error Types
    /// Policy ID mismatch between proof and expected policy
    #[error(
        "Policy mismatch: expected policy '{expected}', but proof was generated for '{actual}'"
    )]
    PolicyMismatch {
        /// Policy id the verifier was asked to enforce.
        expected: String,
        /// Policy id the proof was generated for.
        actual: String,
    },

    /// Limit value mismatch between proof and expected policy
    #[error("Limit mismatch: expected {expected}, but proof was generated for {actual}")]
    LimitMismatch {
        /// Effective limit derived from the verifier's policy.
        expected: u64,
        /// Effective limit the proof was generated against.
        actual: u64,
    },

    /// Invalid hex format in public inputs
    #[error("Invalid hex format in field '{field}': {reason}")]
    InvalidHexFormat {
        /// Public-input field containing the malformed hex.
        field: String,
        /// Why it was rejected — wrong length, or non-canonical casing.
        reason: String,
    },

    /// Unsupported proof version
    #[error("Unsupported proof version {version}: only version {supported} is supported")]
    UnsupportedProofVersion {
        /// Version encoded in the submitted proof.
        version: u32,
        /// The only version this verifier accepts.
        supported: u32,
    },

    /// Witness commitment mismatch
    #[error(
        "Witness commitment mismatch: the proof's commitment doesn't match the expected commitment"
    )]
    WitnessCommitmentMismatch,

    /// Strict verification requires a payload-derived amount binding artifact.
    #[error("Payload amount binding required: {0}")]
    PayloadAmountBindingRequired(String),

    /// Proof is too large
    #[error("Proof too large: {size} bytes exceeds maximum of {max_size} bytes")]
    ProofTooLarge {
        /// Size of the submitted proof, in bytes.
        size: usize,
        /// Hard ceiling enforced before deserialization.
        max_size: usize,
    },
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

    /// Create a policy mismatch error
    pub fn policy_mismatch(expected: &str, actual: &str) -> Self {
        Self::PolicyMismatch {
            expected: expected.to_string(),
            actual: actual.to_string(),
        }
    }

    /// Create a limit mismatch error
    pub fn limit_mismatch(expected: u64, actual: u64) -> Self {
        Self::LimitMismatch { expected, actual }
    }

    /// Create an invalid hex format error
    pub fn invalid_hex(field: &str, reason: &str) -> Self {
        Self::InvalidHexFormat {
            field: field.to_string(),
            reason: reason.to_string(),
        }
    }

    /// Create an unsupported proof version error
    pub fn unsupported_version(version: u32) -> Self {
        Self::UnsupportedProofVersion {
            version,
            supported: PROOF_VERSION,
        }
    }
}

/// Validate a hex string field
///
/// Returns Ok(()) if the hex string is valid, or an error describing the issue.
/// Valid hex strings must:
/// - Have the expected length
/// - Contain only lowercase hex digits (0-9, a-f)
pub fn validate_hex_string(
    field: &str,
    value: &str,
    expected_len: usize,
) -> Result<(), VerifierError> {
    // Check length
    if value.len() != expected_len {
        return Err(VerifierError::invalid_hex(
            field,
            &format!("expected {} characters, got {}", expected_len, value.len()),
        ));
    }

    // Check that all characters are lowercase hex digits
    for (i, c) in value.chars().enumerate() {
        if !c.is_ascii_hexdigit() {
            return Err(VerifierError::invalid_hex(
                field,
                &format!("invalid character '{}' at position {}", c, i),
            ));
        }
        if c.is_ascii_uppercase() {
            return Err(VerifierError::invalid_hex(
                field,
                &format!(
                    "uppercase character '{}' at position {} (must be lowercase)",
                    c, i
                ),
            ));
        }
    }

    Ok(())
}
