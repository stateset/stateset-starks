//! Error types for the sequencer client

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("API error ({status}): {message}")]
    ApiError { status: u16, message: String },

    #[error("Event not found: {0}")]
    EventNotFound(uuid::Uuid),

    #[error("Proof not found: {0}")]
    ProofNotFound(uuid::Uuid),

    #[error("Batch not found: {0}")]
    BatchNotFound(uuid::Uuid),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Policy hash mismatch")]
    PolicyHashMismatch,

    #[error("Public inputs mismatch")]
    PublicInputsMismatch,

    #[error("Invalid public inputs: {0}")]
    InvalidPublicInputs(String),

    #[error("Public inputs event_id mismatch: expected {expected}, got {actual}")]
    PublicInputsEventIdMismatch {
        expected: uuid::Uuid,
        actual: uuid::Uuid,
    },

    #[error("Public inputs hash mismatch: expected {expected}, got {actual}")]
    PublicInputsHashMismatch { expected: String, actual: String },

    #[error("Proof generation failed: {0}")]
    ProofGeneration(String),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Invalid header value: {0}")]
    InvalidHeader(String),

    // Set Chain specific errors
    #[error("Batch already committed on Set Chain: {0}")]
    BatchAlreadyCommitted(uuid::Uuid),

    #[error("Proof already anchored for batch: {0}")]
    ProofAlreadyAnchored(uuid::Uuid),

    #[error("State root mismatch: expected {expected}, got {actual}")]
    StateRootMismatch { expected: String, actual: String },

    #[error("Proof hash mismatch on-chain")]
    ProofHashMismatch,

    #[error("Set Chain transaction failed: {0}")]
    TransactionFailed(String),
}

pub type Result<T> = std::result::Result<T, ClientError>;
