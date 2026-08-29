//! Error types for the sequencer client

use thiserror::Error;

/// Everything that can go wrong talking to the sequencer or Set Chain.
#[derive(Error, Debug)]
pub enum ClientError {
    /// HTTP request failed.
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),

    /// JSON serialization error.
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    /// API error.
    #[error("API error ({status}): {message}")]
    ApiError {
        /// HTTP status returned by the server.
        status: u16,
        /// Server-supplied error message.
        message: String,
    },

    /// Event not found.
    #[error("Event not found: {0}")]
    EventNotFound(uuid::Uuid),

    /// Proof not found.
    #[error("Proof not found: {0}")]
    ProofNotFound(uuid::Uuid),

    /// Batch not found.
    #[error("Batch not found: {0}")]
    BatchNotFound(uuid::Uuid),

    /// Unauthorized.
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Policy hash mismatch.
    #[error("Policy hash mismatch")]
    PolicyHashMismatch,

    /// Public inputs mismatch.
    #[error("Public inputs mismatch")]
    PublicInputsMismatch,

    /// Invalid public inputs.
    #[error("Invalid public inputs: {0}")]
    InvalidPublicInputs(String),

    /// The public inputs describe a different event than the one requested.
    #[error("Public inputs event_id mismatch: expected {expected}, got {actual}")]
    PublicInputsEventIdMismatch {
        /// Event id the caller asked about.
        expected: uuid::Uuid,
        /// Event id carried in the returned public inputs.
        actual: uuid::Uuid,
    },

    /// The returned public inputs do not hash to the expected canonical digest.
    #[error("Public inputs hash mismatch: expected {expected}, got {actual}")]
    PublicInputsHashMismatch {
        /// Canonical hash the caller computed locally.
        expected: String,
        /// Canonical hash of the public inputs the server returned.
        actual: String,
    },

    /// Proof generation failed.
    #[error("Proof generation failed: {0}")]
    ProofGeneration(String),

    /// Invalid proof bundle.
    #[error("Invalid proof bundle: {0}")]
    InvalidProofBundle(String),

    /// Base64 decode error.
    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// Invalid header value.
    #[error("Invalid header value: {0}")]
    InvalidHeader(String),

    /// Invalid base URL for client configuration.
    #[error("Invalid base URL: {0}")]
    InvalidBaseUrl(String),

    // Set Chain specific errors
    /// Batch already committed on Set Chain.
    #[error("Batch already committed on Set Chain: {0}")]
    BatchAlreadyCommitted(uuid::Uuid),

    /// Proof already anchored for batch.
    #[error("Proof already anchored for batch: {0}")]
    ProofAlreadyAnchored(uuid::Uuid),

    /// A batch's state root does not match the chain's expected root.
    #[error("State root mismatch: expected {expected}, got {actual}")]
    StateRootMismatch {
        /// State root the chain expected at this point.
        expected: String,
        /// State root the batch actually declared.
        actual: String,
    },

    /// Proof hash mismatch on-chain.
    #[error("Proof hash mismatch on-chain")]
    ProofHashMismatch,

    /// Set Chain transaction failed.
    #[error("Set Chain transaction failed: {0}")]
    TransactionFailed(String),
}

pub type Result<T> = std::result::Result<T, ClientError>;
