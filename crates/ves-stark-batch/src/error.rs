//! Error types for batch proof operations

use thiserror::Error;

/// Errors that can occur during batch proof operations
#[derive(Debug, Error)]
pub enum BatchError {
    /// An event in the batch does not comply with the policy
    #[error("Event {event_index} not compliant: {message}")]
    EventNotCompliant { event_index: usize, message: String },

    /// Batch is empty
    #[error("Batch cannot be empty")]
    EmptyBatch,

    /// Batch exceeds maximum size
    #[error("Batch size {size} exceeds maximum {max}")]
    BatchTooLarge { size: usize, max: usize },

    /// Invalid previous state root
    #[error("Invalid previous state root")]
    InvalidPrevStateRoot,

    /// State root computation failed
    #[error("State root computation failed: {0}")]
    StateRootError(String),

    /// Trace construction failed
    #[error("Trace construction failed: {0}")]
    TraceConstructionError(String),

    /// Proof generation failed
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    /// Proof verification failed for a specific batch
    #[error("Batch {batch_index} verification failed: {message}")]
    VerificationFailed { batch_index: usize, message: String },

    /// Invalid state chain (new root doesn't match expected)
    #[error(
        "Invalid state chain at batch {batch_index}: expected root {:?}, got {:?}",
        expected,
        actual
    )]
    InvalidStateChain {
        batch_index: usize,
        expected: [u64; 4],
        actual: [u64; 4],
    },

    /// Invalid witness
    #[error("Invalid witness: {0}")]
    InvalidWitness(String),

    /// Deserialization error
    #[error("Deserialization failed: {0}")]
    DeserializationFailed(String),

    /// Serialization error
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),

    /// Invalid public inputs
    #[error("Invalid public inputs: {0}")]
    InvalidPublicInputs(String),

    /// Merkle tree error
    #[error("Merkle tree error: {0}")]
    MerkleTreeError(String),

    /// Witness validation error
    #[error("Witness validation error: {0}")]
    WitnessValidationError(String),
}

/// Result type for batch operations
pub type BatchResult<T> = Result<T, BatchError>;
